import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''
from requests import Session
from zeep import Client
from zeep.transports import Transport
from requests.auth import AuthBase, HTTPBasicAuth
from zeep import helpers
from zeep.cache import SqliteCache
from datetime import datetime
from typing import Dict, Tuple, List, Optional, Union, AnyStr
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


class SymantecAuth(AuthBase):
    def __init__(self, user, password, host):
        self.basic = HTTPBasicAuth(user, password)
        self.host = host

    def __call__(self, r):
        if r.url.startswith(self.host):
            return self.basic(r)
        else:
            return r

''' HELPER FUNCTIONS '''


def myconverter(o):
    if isinstance(o, datetime):
        return o.__str__()


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    demisto.results('ok')


def get_incident_details(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    incident_id: str = args.get('incident_id', '')

    raw_incident: Dict = client.service.incidentDetail(
        incidentId=incident_id,
        includeHistory=True,
        includeViolations=True
    )
    print(raw_incident)
    sys.exit(0)
    human_readable: str
    entry_context = dict()
    raw_response = dict()

    if raw_incident:
        incident = helpers.serialize_object(raw_incident[0])
        raw_response = incident
        human_readable: str = tableToMarkdown(f'Symantec DLP incident {incident_id}', incident, removeNull=True)
        entry_context: dict = {
            'SymantecDLP': {
                'Incident': incident
            }
        }
    else:
        human_readable = 'No incident found.'

    return human_readable, entry_context, raw_response


def list_incidents(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    saved_report_id: str = demisto.params().get('saved_report_id', '')
    if not saved_report_id:
        raise ValueError('Missing saved report ID. Configure it in the integration instance settings.')

    creation_date: datetime = parse_date_range(args.get('creation_date', '1 day'))[0]

    raw_incidents = client.service.incidentList(
        savedReportId=saved_report_id,
        incidentCreationDateLaterThan=creation_date
    )

    human_readable: str
    entry_context = dict()
    raw_response = dict()

    if raw_incidents:
        serialized_incidents: Dict = helpers.serialize_object(raw_incidents)
        raw_response: Dict = serialized_incidents
        incidents = [{
            'ID': incident_id
        } for incident_id in serialized_incidents.get('incidentId', '')]
        human_readable: str = tableToMarkdown(f'Symantec DLP incidents', incidents, removeNull=True)
        entry_context: dict = {
            'SymantecDLP': {
                'Incident': incidents
            }
        }
    else:
        human_readable = 'No incidents found.'

    return human_readable, entry_context, raw_response


def update_incident(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    incident_id: str = args.get('incident_id', '')
    raw_incidents = client.service.incidentList()
    print(raw_incidents)
    sys.exit(0)
    # incident_id: str = args.get('incident_id', '')
    # raw_incident: Dict = client.service.incidentDetail(
    #     incidentId=incident_id,
    #     includeHistory=True,
    #     includeViolations=True
    # )
    # human_readable: str
    # entry_context = dict()
    # raw_response = dict()
    #
    # if raw_incident and isinstance(raw_incident, list):
    #     incident = helpers.serialize_object(raw_incident[0])
    #     raw_response = incident
    #     human_readable: str = tableToMarkdown(f'Symantec DLP incident {incident_id}', incident, removeNull=True)
    #     entry_context: dict = {
    #         'SymantecDLP': {
    #             'Incident': incident
    #         }
    #     }
    # else:
    #     human_readable = 'No incident found.'

    return human_readable, entry_context, raw_response


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    params: Dict = demisto.params()
    server: str = params.get('server', '').rstrip('/')
    credentials: Dict = params.get('credentials', {})
    username: str = credentials.get('identifier', '')
    password: str = credentials.get('password', '')
    verify_ssl = not params.get('insecure', False)
    #proxy = params.get('proxy')
    wsdl: str = f'{server}/ProtectManager/services/v2011/incidents?wsdl'
    session: Session = Session()
    session.auth = SymantecAuth(username, password, server)
    session.verify = verify_ssl
    cache: SqliteCache = SqliteCache(timeout=None)
    transport: Transport = Transport(session=session, cache=cache)
    client: Client = Client(wsdl=wsdl, transport=transport)

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    commands = {
        #'fetch-incidents': fetch_incidents,
        'symantec-dlp-get-incident-details': get_incident_details,
        'symantec-dlp-list-incidents': list_incidents,
        'symantec-dlp-update-incident': update_incident,
    }
    try:
        if command == 'fetch-incidents':
            commands[command](client)
        elif command == 'test-module':
            test_module()
        elif command in commands:
            human_readable, context, raw_response = commands[command](client, demisto.args())
            return_outputs(human_readable, context, raw_response)
    # Log exceptions
    except Exception as e:
        err_msg = f'Error in Symantec DLP integration: {str(e)}'
        return_error(err_msg, error=e)


if __name__ == 'builtins':
    main()
