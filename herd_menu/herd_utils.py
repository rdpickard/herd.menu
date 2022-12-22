import re
import logging
import uuid
import base64

from herd_menu import herd_orm

import arrow
import requests


fqdn_regex = re.compile(
    r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$')
ip_regex = re.compile(
    r'((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|'
    r'25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|'
    r'(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}'
    r'|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|'
    r'(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|'
    r'[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|'
    r'(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|'
    r'((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|'
    r'(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|'
    r'[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|'
    r'(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|'
    r'((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|'
    r'[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|'
    r'(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|'
    r'((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|'
    r'1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|'
    r'1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))')


def log_requests_response(formatted_msg_string, requests_response: requests.Response, level=logging.INFO, logger=logging):
    try:
        log_id = str(uuid.uuid4())

        response_as_string = f"{str(requests_response.url)}\n\n{requests_response.status_code}\n\n{requests_response.headers}\n\n{str(requests_response.text)[:1024]}"
        b64_encoded_response_string = str(base64.b64encode(response_as_string.encode('utf-8')))
        logging.log(level, formatted_msg_string % {"log_id": log_id, "serialized_response": b64_encoded_response_string})

        return log_id

    except Exception as e:
        logging.critical(f"log_requests_response failed to log message due to exception '{e}'")
        logging.exception(e)
        return None


def validate_netlocation(netlocation_string):
    """
    Make sure a string for hostname or hostname:port or ip or ip:port is well formed

    raises ValueError
    """

    if ":" in netlocation_string:
        hostname, hostport = netlocation_string.split(":")
        hostport = int(hostport)
    else:
        hostname = netlocation_string
        hostport = None

    if not ((re.match(fqdn_regex, netlocation_string) and len(netlocation_string) < 256) or re.match(ip_regex, netlocation_string)):
        raise ValueError(
            f"instance_hostname value '{netlocation_string}' does not appear to be a fqdn or and ip 4/6 address")

    if hostport is not None:
        netlocation = ":".join([hostname, hostport])
    else:
        netlocation = hostname

    return netlocation


def scan_mastodon_instance(instance_netlocation, timeout_seconds=3, verify_tls=True, logger=logging):

    netlocation = validate_netlocation(instance_netlocation)

    mastodon_api_instance_endpoint = "https://%(hostname)s/api/v2/instance" % {"hostname": netlocation}

    request_headers = {"Content-Type": "application/json",
                       "User-Agent": "herd.menu scanner email scanner@herd.menu to be excluded (https://herd.menu)"}

    logger.debug(f"scan_mastodon_instance requesting to '{mastodon_api_instance_endpoint}'")

    instance_response = requests.get(mastodon_api_instance_endpoint,
                                     headers=request_headers,
                                     timeout=timeout_seconds,
                                     verify=verify_tls)

    if instance_response.status_code != 200:
        logger.info(f"scan_mastodon_instance request to '{mastodon_api_instance_endpoint}' returned status code {instance_response.status_code} expected 200, bailing")
        return None
    if 'application/json' not in instance_response.headers.get('Content-Type', ''):
        logger.info(f"scan_mastodon_instance request to '{mastodon_api_instance_endpoint}' returned Content-Type {instance_response.headers.get('Content-Type', '')} expected 'application/json', bailing")
        return None

    return instance_response.json()


def get_instance_detail(instance_hostname, db_session, logger=logging):

    instance_doc = None
    instance_record = None
    e = None

    instance_record = db_session.query(herd_orm.MastodonInstanceDocument).filter(herd_orm.MastodonInstanceDocument.instance_hostname == instance_hostname).first()

    if instance_record is not None and (arrow.utcnow() - arrow.get(instance_record.last_successful_scanned_timestamp)).total_seconds() < 5:
        logger.debug("get_instance_detail returning cached record from db")
        return instance_record

    try:
        instance_doc = scan_mastodon_instance(instance_hostname, logger=logger)
    except requests.exceptions.ConnectTimeout as e:
        pass
    except requests.exceptions.SSLError as e:
        pass
    except requests.exceptions.ConnectionError as e:
        pass
    except ValueError:
        pass
    finally:
        if instance_record is None:
            # Create a new record
            instance_record = herd_orm.MastodonInstanceDocument(created_timestamp=arrow.now("UTC").datetime,
                                                                instance_hostname=instance_hostname)
            db_session.add(instance_record)
            db_session.commit()

        instance_record.last_scanned_timestamp = arrow.now("UTC").datetime

        if e is not None:
            logger.info(f"get_instance_detail to {instance_hostname} raised an exception {e}. Could not scan.")
            instance_record.consecutive_scan_failures += 1
        elif instance_doc is not None:
            instance_record.last_successful_scanned_timestamp = arrow.now("UTC").datetime
            instance_record.document_updated_timestamp = arrow.now("UTC").datetime

            if instance_record.document_json is not None:
                instance_record.previous_document_json = instance_record.document_json
            instance_record.document_json = instance_doc

        db_session.commit()

    return instance_record








