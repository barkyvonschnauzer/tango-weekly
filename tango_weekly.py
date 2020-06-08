import json
import os

from azure.cosmos import CosmosClient
from datetime import datetime
from dateutil.relativedelta import relativedelta

####################
# GLOBAL VARIABLES #
####################

##########################################################################
#
# Function name: main
# Input: None.
# Output: TBD
#
# Purpose: Connect to COSMOS DB and compute delta of malicious URLs
#
##########################################################################
def main():

    print ("**** GATHER WEEKLY STATS ****\n")

    submission_results, reporting_results = get_records_from_cosmos()

    print ("**** SUBMISSION RESULTS ****")   
    print (type(submission_results))
    for result in submission_results:
        print (json.dumps(result, indent = True))

    print ("**** REPORTING RESULTS ****")
    print (type(reporting_results))
    for result in reporting_results:
        print (json.dumps(result, indent = True))

    store_stats(submission_results, reporting_results)

##########################################################################
#
# Function name: get_records_from_cosmos
# Input: None.
# Output: TBD
#
# Purpose: Connect to COSMOS DB and pull the two most recent records.
#
##########################################################################
def get_records_from_cosmos():

    print ("**** GET RECORDS FROM COSMOS ****")
    print ("**** QUERY RESULTS CONTAINER ****")
    uri = os.environ.get('ACCOUNT_URI')
    key = os.environ.get('ACCOUNT_KEY')
    database_id = os.environ.get('DATABASE_ID')
    results_container_id = os.environ.get('RESULTS_CONTAINER_ID')
   
    client = CosmosClient(uri, {'masterKey': key})
    print (client)

    database = client.get_database_client(database_id)
    results_container = database.get_container_client(results_container_id)

    reporting_results = list(results_container.query_items(query = 'SELECT TOP 1 * FROM c ORDER BY c._ts DESC', enable_cross_partition_query = True))    

    print ("**** QUERY SUBMISSION CONTAINER ***")

    submission_container_id = os.environ.get('SUBMISSION_CONTAINER_ID')

    client = CosmosClient(uri, {'masterKey': key})
    print (client)

    database = client.get_database_client(database_id)
    submission_container = database.get_container_client(submission_container_id)

    date_str = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
    current_date = datetime.now()

    last_week  = int((datetime.utcnow() - relativedelta(weeks=1)).timestamp())

    query = 'SELECT * FROM c WHERE c._ts > {}'.format(str(last_week))
    submission_results = list(submission_container.query_items(query, enable_cross_partition_query = True))

    return submission_results, reporting_results

##########################################################################
#
# Function name: store_stats
# Input: TBD
# Output: TBD
#
# Purpose: TBD
#
##########################################################################
def store_stats(submission_results, reporting_results):

    print ("**** STORE DELTAS IN COSMOS DB ****")
    uri          = os.environ.get('ACCOUNT_URI')
    key          = os.environ.get('ACCOUNT_KEY')
    database_id  = os.environ.get('DATABASE_ID')
    container_id = os.environ.get('STATS_CONTAINER_ID')

    client = CosmosClient(uri, {'masterKey': key})

    database = client.get_database_client(database_id)
    container = database.get_container_client(container_id)

    # Get date
    date_str = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
    id_date  = int((datetime.utcnow()).timestamp())
    id_date_str = str(id_date)

    # From submission_results, pull: urls_in, urls_net
    urls_in_sum   = 0
    urls_sent_sum = 0

    for record in submission_results:
        urls_in_sum += int(record['n_urls_in'])
        urls_sent_sum += int(record['n_urls_unq'])

    # From reporting_results, pull: n_phishing, 
    #                               n_blocked, 
    #                               n_nothreat, 
    #                               n_suspicious, 
    #                               n_malware,
    #                               n_processing,
    #                               n_unavailable, and
    #                               n_rejected
    # calculate and store the sum.

    n_phishing    = int(reporting_results[0]['n_phishing']) 
    n_blocked     = int(reporting_results[0]['n_blocked'])
    n_nothreat    = int(reporting_results[0]['n_nothreat'])
    n_suspicious  = int(reporting_results[0]['n_suspicious'])
    n_malware     = int(reporting_results[0]['n_malware'])
    n_processing  = int(reporting_results[0]['n_processing'])
    n_unavailable = int(reporting_results[0]['n_unavailable'])
    n_rejected    = int(reporting_results[0]['n_rejected'])

    print ("**** COUNTS ****")
    print ("urls_in: " + str(urls_in_sum))
    print ("urls_sent: " + str(urls_sent_sum))
    print ("phishing_sum: " + str(n_phishing))
    print ("blocked_sum: " + str(n_blocked))
    print ("nothreat_sum: " + str(n_nothreat))
    print ("suspicious_sum: " + str(n_suspicious))
    print ("malware_sum: " + str(n_malware))
    print ("processing_sum: " + str(n_processing))
    print ("unavailable_sum: " + str(n_unavailable))
    print ("rejected_sum: " + str(n_rejected))

    container.upsert_item( { 'id': id_date_str,
                             'date_time': id_date_str,
                             'date': date_str, 
                             'n_urls_received': urls_in_sum,
                             'n_urls_submitted': urls_sent_sum,
                             'n_phishing': n_phishing,
                             'n_blocked': n_blocked,
                             'n_nothreat': n_nothreat,
                             'n_suspicious': n_suspicious, 
                             'n_malware': n_malware, 
                             'n_processing': n_processing,
                             'n_unavailable': n_unavailable,
                             'n_rejected': n_rejected })


if __name__ == "__main__":
    main()
