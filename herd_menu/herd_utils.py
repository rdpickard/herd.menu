import re
import logging
import uuid
import base64
import hashlib

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


def wrap_api_call(instance_netlocation, end_point, timeout_seconds=3, verify_tls=True, logger=logging):

    netlocation = validate_netlocation(instance_netlocation)

    if not end_point.startswith("/"):
        end_point = "/"+end_point

    mastodon_api_endpoint = "https://%(hostname)s%(end_point)s" % {"hostname": netlocation, "end_point": end_point}

    request_headers = {"Content-Type": "application/json",
                       "User-Agent": "herd.menu scanner email scanner@herd.menu to be excluded (https://herd.menu)"}

    logger.debug(f"wrap_api_call requesting to '{mastodon_api_endpoint}'")

    instance_api_response = requests.get(mastodon_api_endpoint,
                                         headers=request_headers,
                                         timeout=timeout_seconds,
                                         verify=verify_tls)

    if instance_api_response.status_code == 401:
        logger.info(
            f"wrap_api_call request to '{mastodon_api_endpoint}' requires authorization. Endpoint returned HTTP status 401, bailing")
        return None
    if instance_api_response.status_code != 200:
        logger.info(
            f"wrap_api_call request to '{mastodon_api_endpoint}' returned status code {instance_api_response.status_code} expected 200, bailing")
        return None
    if 'application/json' not in instance_api_response.headers.get('Content-Type', ''):
        logger.info(
            f"scan_mastodon_blocked_domains request to '{mastodon_api_endpoint}' returned Content-Type {instance_api_response.headers.get('Content-Type', '')} expected 'application/json', bailing")
        return None

    return instance_api_response.json()


def get_mastodon_instance_blocked_domains(instance_netlocation, timeout_seconds=3, verify_tls=True, logger=logging):
    return wrap_api_call(instance_netlocation, "/api/v1/instance/domain_blocks", timeout_seconds, verify_tls, logger)


def get_mastodon_instance_detail(instance_netlocation, timeout_seconds=3, verify_tls=True, logger=logging):
    return wrap_api_call(instance_netlocation, "/api/v2/instance", timeout_seconds, verify_tls, logger)


def scan_mastodon_instance(instance_netlocation, timeout_seconds=3, verify_tls=True, logger=logging):

    instance_detail_document = get_mastodon_instance_detail(instance_netlocation, timeout_seconds=3, verify_tls=True, logger=logging)
    instance_blocked_domains = get_mastodon_instance_blocked_domains(instance_netlocation, timeout_seconds=3, verify_tls=True, logger=logging)

    return instance_detail_document, instance_blocked_domains


def update_instance_blocked_domains(instance_hostname, blocked_domains_list, db_session, logger=logging):

    # create a new slug
    update_slug = str(uuid.uuid4())

    # Create any domains that dont exist AND add all of the blocked domain association to the instance
    for blocked_domain in blocked_domains_list:
        # TODO should check block domain dicts against a JSON schema
        logger.debug(f"Updating blocked domain {blocked_domain}")
        domain_db_instance = herd_orm.get_or_create_no_commit(db_session,
                                                              herd_orm.InternetDomainName,
                                                              domain_name=blocked_domain["domain"])

        if hashlib.sha256(blocked_domain["domain"].encode('ascii')).hexdigest() != blocked_domain["digest"]:
            domain_db_instance.is_obfuscated = True

        domain_db_instance.unobfuscated_source_sha256_hash = blocked_domain["digest"]

        block_relationship = herd_orm.MastodonInstanceBlockedInternetDomainName(
            update_slug=update_slug,
            internet_domain_id=db_session.query(herd_orm.InternetDomainName).filter_by(domain_name=blocked_domain["domain"]).first().id,
            mastodon_instance_document_id=db_session.query(herd_orm.MastodonInstanceDocument).filter_by(instance_hostname=instance_hostname).first().id,
            severity=blocked_domain["severity"],
            comment=blocked_domain["comment"]
        )

        logger.info(block_relationship)

        db_session.add(block_relationship)

    # TODO record diff in blocked domains for instance

    # remove any blocked domain association to the instance with a different slug
    db_session.query(herd_orm.MastodonInstanceBlockedInternetDomainName).filter(herd_orm.MastodonInstanceBlockedInternetDomainName.update_slug != update_slug).delete()


def get_instance_detail(instance_hostname, db_session, logger=logging):

    instance_doc = blocked_domains = None
    in_err = False

    instance_record = db_session.query(herd_orm.MastodonInstanceDocument).filter(herd_orm.MastodonInstanceDocument.instance_hostname == instance_hostname).first()

    if instance_record is not None and (arrow.utcnow() - arrow.get(instance_record.last_successful_scanned_timestamp)).total_seconds() < 5:
        logger.debug("get_instance_detail returning cached record from db")
        return instance_record

    try:
        instance_doc, blocked_domains = scan_mastodon_instance(instance_hostname, logger=logger)
    except requests.exceptions.ConnectTimeout as e:
        logger.info(f"get_instance_detail to {instance_hostname} raised an connection timeout exception {e}. Could not scan.")
        in_err = True
    except requests.exceptions.SSLError as e:
        logger.info(f"get_instance_detail to {instance_hostname} raised an ssl exception {e}. Could not scan.")
        in_err = True
    except requests.exceptions.ConnectionError as e:
        logger.info(f"get_instance_detail to {instance_hostname} raised an connection error {e}. Could not scan.")
        in_err = True
    except ValueError as e:
        logger.info(f"get_instance_detail to {instance_hostname} has a value error {e}. Could not scan.")
        in_err = True
        raise e

    if instance_record is None:
        # Create a new record
        instance_record = herd_orm.MastodonInstanceDocument(created_timestamp=arrow.now("UTC").datetime,
                                                            instance_hostname=instance_hostname)
        db_session.add(instance_record)
        db_session.commit()

    instance_record.last_scanned_timestamp = arrow.now("UTC").datetime

    if in_err:
        logger.debug(f"get_instance_detail bad scan for {instance_hostname} incrementing consecutive_scan_failures")
        instance_record.consecutive_scan_failures += 1
        if instance_record.document_json is not None:
            # bad scan, move the instance document to 'previous'
            instance_record.previous_document_json = instance_record.document_json
            instance_record.document_json = None
    else:
        logger.debug(f"get_instance_detail good scan for {instance_hostname} updating timestamps")
        instance_record.last_successful_scanned_timestamp = arrow.now("UTC").datetime

        if instance_doc is not None:
            instance_record.document_updated_timestamp = arrow.now("UTC").datetime

            if instance_record.document_json is not None:
                instance_record.previous_document_json = instance_record.document_json
            instance_record.document_json = instance_doc

            instance_record.latest_description = instance_doc.get("description","")
            instance_record.latest_accepting_new_users = instance_doc.get("registrations",{}).get("enabled", False)
            instance_record.instance_self_title = instance_doc.get("title","")

            instance_record.instance_software_version = instance_doc.get("version","[unknown]")

            instance_record.latest_combined_rules = "|".join(map(lambda rule_obj: rule_obj.get("text","").replace("|","\|"), instance_doc.get("rules",[])))
            instance_record.latest_combined_language_codes ="|".join(instance_doc.get("languages", []))

        if blocked_domains is not None:
            print(blocked_domains)
            instance_record.blocked_domains_updated_timestamp = arrow.now("UTC").datetime

            #if instance_record.blocked_domains_json is not None:
            #    instance_record.previous_blocked_domains_json = instance_record.blocked_domains_json
            #instance_record.blocked_domains_json = blocked_domains
            update_instance_blocked_domains(instance_hostname, blocked_domains, db_session, logger)

            instance_record.latest_combined_blocked_domains = "|".join(map(lambda domain_obj: domain_obj.get("domain","").replace("|","\|"), blocked_domains))

    db_session.commit()

    return not in_err, instance_record


def get_blocked_domains_for_instance_by_name(instance_name, db_session, logger=logging):

    m_instance = db_session.query(herd_orm.MastodonInstanceDocument).filter(herd_orm.MastodonInstanceDocument.instance_hostname == instance_name).first()

    for bd in m_instance.blocked_domains:
        if bd.is_obfuscated:
            logger.info(f"OBFUSCATED {bd.domain_name}")
        else:
            logger.info(f"CLEAR {bd.domain_name}")







