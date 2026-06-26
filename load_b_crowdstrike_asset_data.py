# Databricks notebook source
# MAGIC %pip install crowdstrike-falconpy

# COMMAND ----------

dbutils.library.restartPython()

# COMMAND ----------

import os
import requests
from falconpy import Discover
from datetime import datetime, timedelta, timezone
import pandas as pd
from pyspark.sql.functions import current_timestamp, col, lit
import logging
from dateutil.relativedelta import relativedelta

# COMMAND ----------

# MAGIC %run /Workspace/common/load_commons

# COMMAND ----------

# MAGIC %run ./job_commons

# COMMAND ----------

# MAGIC %run /Workspace/Logging/logging_v1

# COMMAND ----------

# MAGIC %run ./email_utils

# COMMAND ----------

schema_name='b_di'
table_name = 'cyberoperations_crowdstrike_discovered_hosts_combined'
output_table_name = f"{schema_name}.{table_name}"

# COMMAND ----------

insert_process_log(schema_name, table_name)

# COMMAND ----------

workspace_configs = get_workspace_configs()
job_configs = get_job_configs()
keyvault_secret = job_configs["keyvault_secret"]
secret_scope = workspace_configs["secret_scope"]
client_id=job_configs["client_id"]
batch_size = job_configs["batch_size"]
client_secret = dbutils.secrets.get(scope=secret_scope, key=keyvault_secret)

# COMMAND ----------

# DBTITLE 1,Cell 11
def get_third_party_facet(client_id, client_secret):
    auth_url = "https://api.us-2.crowdstrike.com/oauth2/token"
    endpoint = "https://api.us-2.crowdstrike.com/discover/combined/hosts/v1"
    auth_response = requests.post(
        auth_url,
        data={"client_id": client_id, "client_secret": client_secret}
    )
    access_token = auth_response.json().get("access_token")
    headers = {"Authorization": f"Bearer {access_token}"}
    now_utc = datetime.now(timezone.utc)
    range_start = now_utc - relativedelta(years=10)
    min_window = timedelta(hours=1)

    def to_cs_ts(dt):
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def get_error_payload(response):
        try:
            return response.json()
        except Exception:
            return response.text

    def get_entity_type_values():
        try:
            if spark.catalog.tableExists(output_table_name):
                values = [
                    row["entity_type"]
                    for row in spark.sql(
                        f"""
                        SELECT DISTINCT entity_type
                        FROM {output_table_name}
                        WHERE adh_created >= current_date() - INTERVAL 30 DAYS
                          AND entity_type IS NOT NULL
                        """
                    ).collect()
                ]
                if values:
                    return sorted(values)
        except Exception:
            pass
        return ["managed", "unsupported", "unmanaged"]

    entity_type_values = get_entity_type_values()

    def build_filter(window_start, window_end, entity_type):
        return "+".join([
            f"entity_type:'{entity_type}'",
            f"first_seen_timestamp:>='{to_cs_ts(window_start)}'",
            f"first_seen_timestamp:<'{to_cs_ts(window_end)}'"
        ])

    def fetch_window(window_start, window_end, entity_type):
        results = []
        params = {
            "facet": "third_party",
            "filter": build_filter(window_start, window_end, entity_type),
            "limit": 1000
        }
        while True:
            response = requests.get(endpoint, headers=headers, params=params)
            if response.status_code != 200:
                error_payload = get_error_payload(response)
                if response.status_code == 400 and (window_end - window_start) > min_window:
                    midpoint = window_start + (window_end - window_start) / 2
                    left_results = fetch_window(window_start, midpoint, entity_type)
                    right_results = fetch_window(midpoint, window_end, entity_type)
                    return left_results + right_results
                logging.error(f"Error getting third party facets {response.status_code} {error_payload}")
                update_process_log_fail(f"Error getting third party facets {response.status_code} {error_payload}")
                raise Exception(f"Error getting third party facets {response.status_code} {error_payload}")
            data = response.json()
            results.extend(data.get("resources") or [])
            pagination = data.get("meta", {}).get("pagination", {})
            after = pagination.get("after")
            if after:
                params["after"] = after
            else:
                break
        return results

    results = []
    for entity_type in entity_type_values:
        results.extend(fetch_window(range_start, now_utc, entity_type))

    result = pd.DataFrame(results)
    return result


# COMMAND ----------

def chunk_list(lst):
    for i in range(0,len(lst), 100):
        yield lst[i:i + 100]

# COMMAND ----------

def get_hosts(client_id, client_secret, hosts):
    falcon = Discover(client_id=client_id, client_secret=client_secret)    
    host_props = falcon.get_hosts(ids=hosts)
    if host_props['status_code'] !=200:
        logging.error(f"Error getting hosts properties {host_props['status_code']} {host_props['body']['errors']}")
        update_process_log_fail(f"Error getting hosts properties {host_props['status_code']} {host_props['body']['errors']}")
        raise Exception(f"Error getting hosts properties {host_props['status_code']} {host_props['body']['errors']}")
    return host_props['body']['resources']

# COMMAND ----------

third_party_df = get_third_party_facet(client_id,client_secret)

# COMMAND ----------

# hosts = third_party_df['id'].tolist()
# all_hosts = []
# for chunk in chunk_list(hosts):
#     all_hosts.extend(get_hosts(client_id, client_secret, chunk))
# df = pd.DataFrame(all_hosts)
# # select only two columns to avoid error
# df = df[['id','cid','criticality','discoverer_criticalities']]
# # join with third party data
# final_df = third_party_df.merge(df, left_on=['id','cid'], right_on=['id','cid'], how='inner')

# COMMAND ----------

field_names=list(third_party_df.columns)
sparkDF = spark.createDataFrame(third_party_df)
final_df = sparkDF.select([col(c).cast("string") for c in sparkDF.columns])
final_df = final_df.withColumn("adh_created", current_timestamp())
try:
    final_df.write.mode("append").option("mergeSchema", "true").format("delta").saveAsTable(output_table_name)
    update_process_log_success()
except Exception as e:
    logging.error(f"Error: {e}")
    update_process_log_fail(e)
    raise Exception("Process failed with exception {e}")