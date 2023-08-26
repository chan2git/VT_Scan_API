import requests
import time
import json
import base64

# To obtain an API key, sign up for a VirusTotal account and assign your personal API key into the var api_key as a string
api_key ='<insert your API key here>'




def vt_scanurl(ioc):
    # A function that takes in a URL and returns a VirusTotal Analysis ID


    # URL where HTTP Post request is made
    url = "https://www.virustotal.com/api/v3/urls"

    # Payload and header information
    payload = {"url": ioc}
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
        "content-type": "application/x-www-form-urlencoded"
    }

    # Making the API request and storing reponse into var response
    response = requests.post(url, data=payload, headers=headers)

    # Prints the response
    print(response.text)





def vt_urlreport(ioc):
    # A function that takes in a URL and returns a VirusTotal URL analysis report

    # Converting URL into base64 (required format)
    url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")

    # URL where HTTP Get request is made
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    # Header information
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    # Making the API request and storing reponse into var response
    response = requests.get(url, headers=headers)

    # Prints the response
    print(response.text)



def vt_urlcomment(ioc, limit=None):
    # A function that takes in a URL and returns Comment objects regarding the specific URL.
    # The VirusTotal community can add additional information to an object's report through adding comments
    # The limit parameter dictates the max quantity of output displayed


    # Use case if no output limit is specified
    if limit is None:

        # Converting URL into base64 (required format)
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")

        # URL where HTTP Get request is made
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}/comments"

        # Header information
        headers = {
        "accept": "application/json",
        "x-apikey": api_key
        }

        # Making the API request and storing reponse into var response
        response = requests.get(url, headers=headers)

        # Prints the response
        print(response.text)

    # Use case if output limit is specified
    else:

        # Converting URL into base64 (required format)
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")

        # URL where HTTP Get request is made
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}/comments?limit={limit}"

        # Header information
        headers = {
        "accept": "application/json",
        "x-apikey": api_key
        }

        # Making the API request and storing reponse into var response
        response = requests.get(url, headers=headers)

        # Prints the response
        print(response.text)





def vt_urlobject(ioc, relationship, limit=None):
    # A function that takes in a URL and returns relationship objects regarding the specific URL
    # VirusTotal Relationship objects (non-premium):
    #       'comments',
    #       'graphs',
    #       'last_serving_ip_address',
    #       'network_location',
    #       'related_comments',
    # The limit parameter dictates the max quantity of output displayed

    # Use case if no output limit is specified
    if limit is None:
        
        # Converting URL into base64 (required format)
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")

        # URL where HTTP Get request is made
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}/{relationship}"

        # Header information
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }

        # Making the API request and storing reponse into var response
        response = requests.get(url, headers=headers)

        # Prints the response
        print(response.text)

    # Use case if output limit is specified
    else:
        
        # Converting URL into base64 (required format)
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")

        # URL where HTTP Get request is made
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}/{relationship}?limit={limit}"

        # Header information
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }

        # Making the API request and storing reponse into var response
        response = requests.get(url, headers=headers)

        # Prints the response
        print(response.text)




def vt_urlvote(ioc, limit=None):
    # A function that takes in a URL and returns Vote objects regarding the specific URL
    # The limit parameter dictates the max quantity of output displayed

    # Use case if no output limit is specified
    if limit is None:

        # Converting URL into base64 (required format)
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")

        # URL where HTTP Get request is made
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}/votes"

        # Header information
        headers = {
            "accept": "application/json",
            "x-apikey": "ee70285741a307de82e27a4ab3c5d6a52881907e30be976206d49cdd252c660d"
        }

        # Making the API request and storing reponse into var response
        response = requests.get(url, headers=headers)

        print(response.text)

    else:
        # Converting URL into base64 (required format)
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")

        # URL where HTTP Get request is made
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}/votes?limit={limit}"

        # Header information
        headers = {
            "accept": "application/json",
            "x-apikey": "ee70285741a307de82e27a4ab3c5d6a52881907e30be976206d49cdd252c660d"
        }

        # Making the API request and storing reponse into var response
        response = requests.get(url, headers=headers)

        # Prints the response
        print(response.text) 












################################################ FOOTNOTES ################################################

#############################
# Version:    1.00          #
# Date:       08/26/2023    #
# Coder:      CH @chan2git  #
#############################

############################################################# 
# Sign up for your API key at:                              #
# https://virustotal.com                                    #
#                                                           #
#                                                           #
# API documentation:                                        #
# https://developers.virustotal.com/reference/overview      #
#############################################################



















