import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''

from datetime import datetime, timedelta
import json
import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

ALL_EVENTS = "All"
ISSUES_EVENTS = "Issues"
BLOCKED_CLICKS = "Blocked Clicks"
PERMITTED_CLICKS = "Permitted Clicks"
BLOCKED_MESSAGES = "Blocked Messages"
DELIVERED_MESSAGES = "Delivered Messages"

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

""" Helper functions """


def get_now():
    """ A wrapper function of datetime.now
    helps handle tests

    Returns:
        datetime: time right now
    """
    return datetime.now()


def get_fetch_times(last_fetch):
    """ Get list of every hour since last_fetch
    Args:
        last_fetch (datetime or str): last_fetch time

    Returns:
        List[str]: list of str represents every hour since last_fetch
    """
    now = get_now() - timedelta(seconds=30)
    times = list()
    if isinstance(last_fetch, str):
        times.append(last_fetch)
        last_fetch = datetime.strptime(last_fetch, DATE_FORMAT)
    elif isinstance(last_fetch, datetime):
        times.append(last_fetch.strftime(DATE_FORMAT))
    while now - last_fetch > timedelta(hours=1):
        last_fetch += timedelta(hours=1)
        times.append(last_fetch.strftime(DATE_FORMAT))
    return times


class Client:
    def __init__(self, proofpoint_url, api_version, verify, service_principal, secret, proxies):
        self.base_url = urljoin(proofpoint_url, api_version)
        self.verify = verify
        self.service_principal = service_principal
        self.secret = secret
        self.proxies = proxies

    def http_request(self, method, url_suffix, params=None, data=None):
        full_url = urljoin(self.base_url, url_suffix)

        res = requests.request(
            method,
            full_url,
            verify=self.verify,
            params=params,
            json=data,
            auth=(self.service_principal, self.secret),
            proxies=self.proxies
        )

        if res.status_code not in [200, 204]:
            raise ValueError(f'Error in API call to Proofpoint TAP {res.status_code}. Reason: {res.text}')

        try:
            return res.json()
        except Exception:
            raise ValueError(f"Failed to parse http response to JSON format. Original response body: \n{res.text}")

    def get_events(self, interval=None, since_time=None, since_seconds=None, threat_type=None, threat_status=None,
                   event_type_filter="All"):

        if not interval and not since_time and not since_seconds:
            raise ValueError("Required to pass interval or sinceTime or sinceSeconds.")

        query_params = {
            "format": "json"
        }
        query_params.update(
            assign_params(
                interval=interval,
                sinceTime=since_time,
                sinceSeconds=since_seconds,
                threatStatus=threat_status,
                threatType=threat_type
            )
        )

        url_route = {
            "All": "/all",
            "Issues": "/issues",
            "Blocked Clicks": "/clicks/blocked",
            "Permitted Clicks": "/clicks/permitted",
            "Blocked Messages": "/messages/blocked",
            "Delivered Messages": "/messages/delivered"
        }[event_type_filter]

        events = self.http_request("GET", urljoin('siem', url_route), params=query_params)

        return events

    def get_forensics(self, threat_id=None, campaign_id=None, include_campaign_forensics=None):
        if threat_id and campaign_id:
            raise DemistoException('threadId and campaignID supplied, supply only one of them')
        if include_campaign_forensics and campaign_id:
            raise DemistoException('includeCampaignForensics can be true only with threadId')
        params = assign_params(
            threatId=threat_id,
            campaingId=campaign_id,
            includeCampaignForensics=include_campaign_forensics)
        return self.http_request('GET', 'forensics', params=params)


def test_module(client, first_fetch_time, event_type_filter):
    """
    Performs basic get request to get item samples
    """
    since_time, _ = parse_date_range(first_fetch_time, date_format=DATE_FORMAT, utc=True)
    client.get_events(since_time=since_time, event_type_filter=event_type_filter)

    # test was successful
    return 'ok'


def get_forensic_command(client: Client, args):
    """
    TODO: this
    Args:
        client (object):
    """
    threat_id = args.get('threatId')
    campaign_id = args.get('campaignId')
    include_campaign_forensics = args.get('includeCampaignForensics') == 'true'
    raw_forensics = client.get_forensics(
        threat_id=threat_id,
        campaign_id=campaign_id,
        include_campaign_forensics=include_campaign_forensics
    )
    reports = raw_forensics.get('reports', [])





@logger
def get_events_command(client, args):
    interval = args.get("interval")
    threat_type = argToList(args.get("threatType"))
    threat_status = args.get("threatStatus")
    since_time = args.get("sinceTime")
    since_seconds = int(args.get("sinceSeconds")) if args.get("sinceSeconds") else None
    event_type_filter = args.get("eventTypes")

    raw_events = client.get_events(interval, since_time, since_seconds, threat_type, threat_status, event_type_filter)

    return (
        tableToMarkdown("Proofpoint Events", raw_events),
        {
            'Proofpoint.MessagesDelivered(val.GUID == obj.GUID)': raw_events.get("messagesDelivered"),
            'Proofpoint.MessagesBlocked(val.GUID == obj.GUID)': raw_events.get("messagesBlocked"),
            'Proofpoint.ClicksBlocked(val.GUID == obj.GUID)': raw_events.get("clicksBlocked"),
            'Proofpoint.ClicksPermitted(val.GUID == obj.GUID)': raw_events.get("clicksPermitted")
        },
        raw_events
    )


@logger
def fetch_incidents(client, last_run, first_fetch_time, event_type_filter, threat_type, threat_status):
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch')

    # Handle first time fetch, fetch incidents retroactively
    if last_fetch is None:
        last_fetch, _ = parse_date_range(first_fetch_time, date_format=DATE_FORMAT, utc=True)

    incidents = []
    fetch_times = get_fetch_times(last_fetch)
    fetch_time_count = len(fetch_times)
    for index, fetch_time in enumerate(fetch_times):
        if len(incidents) > 50:
            break
        if index < fetch_time_count - 1:
            raw_events = client.get_events(interval=fetch_time + "/" + fetch_times[index + 1],
                                           event_type_filter=event_type_filter,
                                           threat_status=threat_status, threat_type=threat_type)
        else:
            raw_events = client.get_events(interval=fetch_time + "/" + get_now().strftime(DATE_FORMAT),
                                           event_type_filter=event_type_filter,
                                           threat_status=threat_status, threat_type=threat_type)

        for raw_event in raw_events.get("messagesDelivered", []):
            if len(incidents) > 50:
                break
            raw_event["type"] = "messages delivered"
            event_guid = raw_events.get("GUID", "")
            incident = {
                "name": f"Proofpoint - Message Delivered - {event_guid}",
                "rawJSON": json.dumps(raw_event)
            }

            if raw_event["messageTime"] > last_fetch:
                last_fetch = raw_event["messageTime"]

            for threat in raw_event.get("threatsInfoMap", []):
                if threat["threatTime"] > last_fetch:
                    last_fetch = threat["threatTime"]

            incidents.append(incident)

        for raw_event in raw_events.get("messagesBlocked", []):
            if len(incidents) > 50:
                break

            raw_event["type"] = "messages blocked"
            event_guid = raw_events.get("GUID", "")
            incident = {
                "name": "Proofpoint - Message Blocked - {}".format(event_guid),
                "rawJSON": json.dumps(raw_event)
            }

            if raw_event["messageTime"] > last_fetch:
                last_fetch = raw_event["messageTime"]

            for threat in raw_event.get("threatsInfoMap", []):
                if threat["threatTime"] > last_fetch:
                    last_fetch = threat["threatTime"]

            incidents.append(incident)

        for raw_event in raw_events.get("clicksPermitted", []):
            if len(incidents) > 50:
                break
            raw_event["type"] = "clicks permitted"
            event_guid = raw_events.get("GUID", "")
            incident = {
                "name": "Proofpoint - Click Permitted - {}".format(event_guid),
                "rawJSON": json.dumps(raw_event)
            }

            if raw_event["clickTime"] > last_fetch:
                last_fetch = raw_event["clickTime"]

            if raw_event["threatTime"] > last_fetch:
                last_fetch = raw_event["threatTime"]

            incidents.append(incident)

        for raw_event in raw_events.get("clicksBlocked", []):
            if len(incidents) > 50:
                break
            raw_event["type"] = "clicks blocked"
            event_guid = raw_events.get("GUID", "")
            incident = {
                "name": "Proofpoint - Click Blocked - {}".format(event_guid),
                "rawJSON": json.dumps(raw_event)
            }

            if raw_event["clickTime"] > fetch_time:
                last_fetch = raw_event["clickTime"]

            if raw_event["threatTime"] > fetch_time:
                last_fetch = raw_event["threatTime"]

            incidents.append(incident)
    last_fetch_datetime = get_now()
    next_run = {'last_fetch': last_fetch_datetime}

    return next_run, incidents


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    service_principal = params.get('credentials', {}).get('identifier')
    secret = params.get('credentials', {}).get('password')

    # Remove trailing slash to prevent wrong URL path to service
    server_url = params['url'][:-1] if (params['url'] and params['url'].endswith('/')) else params['url']
    api_version = params.get('api_version')

    verify_certificate = not params.get('insecure', False)
    # How many time before the first fetch to retrieve incidents
    fetch_time = params.get('fetch_time', '60 minutes')

    threat_status = argToList(params.get('threat_status'))

    threat_type = argToList(params.get('threat_type'))

    event_type_filter = params.get('events_type')

    # Remove proxy if not set to true in params
    proxies = handle_proxy()

    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        client = Client(server_url, api_version, verify_certificate, service_principal, secret, proxies)
        commands = {
            'proofpoint-get-events': get_events_command,
            'proofpoint-get-forensic': get_forensic_command
        }
        if command == 'test-module':
            results = test_module(client, fetch_time, event_type_filter)
            return_outputs(results, None)

        elif command == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=fetch_time,
                event_type_filter=event_type_filter,
                threat_status=threat_status,
                threat_type=threat_type
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command in ():
            return_outputs(*commands[command](client, demisto.args()))

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
