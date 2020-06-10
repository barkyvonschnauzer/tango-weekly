import json
import os
import requests

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

    netcraft_characterization_results_json = {}
    netcraft_stats = {}
    uuid_list = []

    uuid_list, n_urls_received, n_urls_submitted = get_submission_info_from_cosmos()

    print ("**** URL Stats ****")
    print ("Number of URLs received: " + str(n_urls_received))
    print ("Number of URLs submitted: " + str(n_urls_submitted))
    print ("Number of UUIDs to check: " + str(len(uuid_list)), flush=True)

    #print ("**** UUID List ****")
    #for uuid in uuid_list:
    #    print (uuid)

    if len(uuid_list) != 0:
        netcraft_characterization_results_json = check_URLs_state_netcraft_by_UUID(uuid_list)
        netcraft_stats = get_netcraft_stats(netcraft_characterization_results_json)
        store_stats(netcraft_stats, n_urls_received, n_urls_submitted)

##########################################################################
#
# Function name: get_submission_info_from_cosmos
# Input: None.
# Output: TBD
#
# Purpose: Connect to COSMOS DB and pull the two most recent records.
#
##########################################################################
def get_submission_info_from_cosmos():

    print ("**** GET NETCRAFT UUIDs FROM COSMOS ****")
    print ("**** QUERY RESULTS CONTAINER ****")
    uri = os.environ.get('ACCOUNT_URI')
    key = os.environ.get('ACCOUNT_KEY')
    database_id = os.environ.get('DATABASE_ID')
    submission_container_id = os.environ.get('SUBMISSION_CONTAINER_ID')
   
    client = CosmosClient(uri, {'masterKey': key})
    #print (client)

    database = client.get_database_client(database_id)
    submission_container = database.get_container_client(submission_container_id)

    last_week  = int((datetime.utcnow() - relativedelta(weeks=1)).timestamp())

    #print('Today: ' + current_date.strftime('%Y-%m-%d %H:%M:%S'))
    #print('Yesterday: ' + date_yesterday.strftime('%Y-%m-%d %H:%M:%S'))

    print ("Query db for UUIDs since yesterday\n")

    #print(str(yesterday))

    # Get list of UUIDs
    query = 'SELECT DISTINCT VALUE c.id FROM c WHERE c._ts > {}'.format(str(last_week))
    uuid_query_results = list(submission_container.query_items(query, enable_cross_partition_query = True))

    query = 'SELECT * FROM c WHERE c._ts > {}'.format(str(last_week))
    submission_results = list(submission_container.query_items(query, enable_cross_partition_query = True))

    # From submission_results, pull: urls_in, urls_net
    urls_received  = 0
    urls_submitted = 0

    for record in submission_results:
        urls_received  += int(record['n_urls_in'])
        urls_submitted += int(record['n_urls_unq'])

    return uuid_query_results, urls_received, urls_submitted


##########################################################################
#
# Function name: check_URLs_state_netcraft_by_UUID
# Input: uuid returned from Netcraft submission,
#
# Output:
#
# Purpose: to check the characterization of each URL submitted to
#          Netcraft.
#          Possible results:
#          - processing
#          - no threats
#          - unavailable
#          - phishing
#          - already blocked
#          - suspicious
#          - malware
#          - rejected (was already submitted)
#
##########################################################################
def check_URLs_state_netcraft_by_UUID(uuid_list):

    print("\n***** Query Netcraft for URL classification by UUID *****\n", flush=True)

    URL_characterization_results = {}

    for uuid in uuid_list:
        #print("\n***** " + uuid + " *****", flush=True)

        netcraftSubmissionCheck_url = "https://report.netcraft.com/api/v2/submission/" + uuid + "/urls"

        # Check URLs with netcraft service
        r_get = requests.get(netcraftSubmissionCheck_url, timeout=2)

        #print("Netcraft submission check response status code (" + uuid + "): " + str(r_get.status_code))
        #print(r_get.json())

        if r_get.status_code == 200:
            if r_get.json():
                print("Results for uuid:" + uuid + " available.")

                # Get results
                for entry in r_get.json()['urls']:
                    url = entry['url']
                    url_state = entry['url_state']
                    
                    URL_characterization_results[url] = {'characterization':url_state}
                    #print(url,URL_characterization_results[url],flush=True)

    print ("**** URL Characterization Results from Netcraft ****", flush=True)
#    for k,v in URL_characterization_results.items():
#        print (k,v)

    return URL_characterization_results



##########################################################################
#
# Function name: get_netcraft_stats
# Input: dictionary of netcraft results returned by API call.
# Output: dictionary to be saved in Cosmos
#
# Purpose: To sort and view the aggregated results returned by netcraft
#          per classification bin.
#
#
##########################################################################
def get_netcraft_stats(netcraft_characterization_results):
    print ("***** Sort Netcraft Characterization Results *****\n", flush=True)

    # keys by value:
    #      - processing
    #      - no threats
    #      - unavailable
    #      - phishing
    #      - already blocked
    #      - suspicious
    #      - malware
    #      - rejected (was already submitted)

    phishing_results   = []
    already_blocked    = []
    no_threats         = []
    suspicious_results = []
    malware_results    = []
    processing         = []
    unavailable        = []
    rejected           = []

    print ("\n***** PHISHING *****")
    phishing_results = [url for url, status in netcraft_characterization_results.items() if status['characterization'] == "phishing"]
    print(len(phishing_results))
    print (phishing_results)

    print ("\n***** ALREADY BLOCKED *****")
    already_blocked = [url for url, status in netcraft_characterization_results.items() if status['characterization'] == "already blocked"]
    print(len(already_blocked))
    print (already_blocked)

    print ("\n***** NO THREATS *****")
    no_threats = [url for url, status in netcraft_characterization_results.items() if status['characterization'] == "no threats"]
    print(len(no_threats))
    print (no_threats)

    print ("\n***** SUSPICIOUS *****")
    suspicious_results = [url for url, status in netcraft_characterization_results.items() if status['characterization'] == "suspicious"]
    print(len(suspicious_results))
    print (suspicious_results)

    print ("\n***** MALWARE *****")
    malware_results = [url for url, status in netcraft_characterization_results.items() if status['characterization'] == "malware"]
    print(len(malware_results))
    print (malware_results)

    print ("\n***** PROCESSING *****")
    processing = [url for url, status in netcraft_characterization_results.items() if status['characterization'] == "processing"]
    print(len(processing))
    print (processing)

    print ("\n***** UNAVAILABLE *****")
    unavailable = [url for url, status in netcraft_characterization_results.items() if status['characterization'] == "unavailable"]
    print(len(unavailable))
    print (unavailable)

    print ("\n***** REJECTED *****")
    rejected = [url for url, status in netcraft_characterization_results.items() if status['characterization'] == "rejected"]
    print(len(rejected))
    print (rejected)

    n_phishing    = len(phishing_results)
    n_blocked     = len(already_blocked)
    n_nothreat    = len(no_threats)
    n_suspicious  = len(suspicious_results)
    n_malware     = len(malware_results)
    n_processing  = len(processing)
    n_unavailable = len(unavailable)
    n_rejected    = len(rejected)

    print ("n_phishing: " + str(n_phishing))
    print ("n_blocked: " + str(n_blocked))
    print ("n_nothreat: " + str(n_nothreat))
    print ("n_suspicious: " + str(n_suspicious))
    print ("n_malware: " + str(n_malware))
    print ("n_processing: " + str(n_processing))
    print ("n_unavailable: " + str(n_unavailable))
    print ("n_rejected: " + str(n_rejected), flush=True)

    results = {'phishing': n_phishing, 
               'blocked': n_blocked, 
               'nothreat': n_nothreat, 
               'suspicious': n_suspicious, 
               'malware': n_malware, 
               'processing': n_processing,
               'unavailable': n_unavailable,
               'rejected': n_rejected}

    return results

##########################################################################
#
# Function name: get_NETCRAFT_uuids_from_Cosmos
# Input:
# Output:
#
# Purpose: Connect to the COSMOS DB.
#
##########################################################################
def get_netcraft_uuids_from_cosmos():

    print ("\n***** Connect to COSMOS DB *****\n")
    uri          = os.environ.get('ACCOUNT_URI')
    key          = os.environ.get('ACCOUNT_KEY')
    database_id  = os.environ.get('DATABASE_ID')
    container_id = os.environ.get('SUBMISSION_CONTAINER_ID')

    client = CosmosClient(uri, {'masterKey': key})
    print (client)

    database = client.get_database_client(database_id)
    container = database.get_container_client(container_id)

    client = CosmosClient(uri, {'masterKey': key})

    date_str = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
    current_date = datetime.now()
    date_yesterday = current_date - timedelta(days=1)

    #print('Today: ' + current_date.strftime('%Y-%m-%d %H:%M:%S'))
    #print('Yesterday: ' + date_yesterday.strftime('%Y-%m-%d %H:%M:%S'))

    print ("Query db for UUIDs since yesterday\n")

    yesterday  = int((datetime.utcnow() - relativedelta(days=1)).timestamp())

    #print(str(yesterday))

    query = 'SELECT DISTINCT VALUE c.id FROM c WHERE c._ts > {}'.format(str(yesterday))
    uuid_query_results = list(container.query_items(query, enable_cross_partition_query = True))

    print (uuid_query_results)

    #for result in uuid_query_results:
    #    print (json.dumps(result, indent=True))

    return uuid_query_results


##########################################################################
#
# Function name: store_stats
# Input: TBD
# Output: TBD
#
# Purpose: TBD
#
##########################################################################
def store_stats(netcraft_stats, n_urls_received, n_urls_submitted):

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

    # From reporting_results, pull: phishing, 
    #                               blocked, 
    #                               nothreat, 
    #                               suspicious, 
    #                               malware,
    #                               processing,
    #                               unavailable, and
    #                               rejected
    # calculate and store the sum.

    if netcraft_stats:  # not empty
        n_phishing    = int(netcraft_stats['phishing']) 
        n_blocked     = int(netcraft_stats['blocked'])
        n_nothreat    = int(netcraft_stats['nothreat'])
        n_suspicious  = int(netcraft_stats['suspicious'])
        n_malware     = int(netcraft_stats['malware'])
        n_processing  = int(netcraft_stats['processing'])
        n_unavailable = int(netcraft_stats['unavailable'])
        n_rejected    = int(netcraft_stats['rejected'])

        print ("**** COUNTS ****")
        print ("urls_received: " + str(n_urls_received))
        print ("urls_submitted: " + str(n_urls_submitted))
        print ("phishing_sum: " + str(n_phishing))
        print ("blocked_sum: " + str(n_blocked))
        print ("nothreat_sum: " + str(n_nothreat))
        print ("suspicious_sum: " + str(n_suspicious))
        print ("malware_sum: " + str(n_malware))
        print ("processing_sum: " + str(n_processing))
        print ("unavailable_sum: " + str(n_unavailable))
        print ("rejected_sum: " + str(n_rejected), flush=True)

        container.upsert_item( { 'id': id_date_str,
                                 'date_time': id_date_str,
                                 'date': date_str, 
                                 'n_urls_received': n_urls_received,
                                 'n_urls_submitted': n_urls_submitted,
                                 'n_phishing': n_phishing,
                                 'n_blocked': n_blocked,
                                 'n_nothreat': n_nothreat,
                                 'n_suspicious': n_suspicious, 
                                 'n_malware': n_malware, 
                                 'n_processing': n_processing,
                                 'n_unavailable': n_unavailable,
                                 'n_rejected': n_rejected })

    else: # empty
        print ("**** COUNTS ****")
        print ("urls_received: " + str(n_urls_received))
        print ("urls_submitted: " + str(n_urls_submitted))

        container.upsert_item( { 'id': id_date_str,
                                 'date_time': id_date_str,
                                 'date': date_str,
                                 'n_urls_received': n_urls_received,
                                 'n_urls_submitted': n_urls_submitted })

if __name__ == "__main__":
    main()
