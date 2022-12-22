import uuid
import json
import logging
import base64
import sys
import urllib

import requests
import arrow
import jsonschema
import sqlalchemy
import sqlalchemy.orm
import sqlalchemy.types
import sqlalchemy.ext.mutable

Base = sqlalchemy.orm.declarative_base()


class MutableDict(sqlalchemy.ext.mutable.Mutable, dict):
    # https://docs.sqlalchemy.org/en/14/orm/extensions/mutable.html

    @classmethod
    def coerce(cls, key, value):
        if not isinstance(value, MutableDict):
            if isinstance(value, dict):
                return MutableDict(value)

            # this call will raise ValueError
            return sqlalchemy.ext.mutable.Mutable.coerce(key, value)
        else:
            return value

    def __setitem__(self, key, value):
        dict.__setitem__(self, key, value)
        self.changed()

    def __delitem__(self, key):
        dict.__delitem__(self, key)
        self.changed()


class JSONEncodedDict(sqlalchemy.types.TypeDecorator):
    # https://docs.sqlalchemy.org/en/14/core/custom_types.html#marshal-json-strings

    """Represents an immutable structure as a json-encoded string.

    Usage::

        JSONEncodedDict(255)

    """

    impl = sqlalchemy.types.VARCHAR

    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = json.dumps(value)

        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = json.loads(value)
        return value


json_db_type = MutableDict.as_mutable(JSONEncodedDict)


class MastodonInstanceDocument(Base):
    __tablename__ = "herd_menu_mastodon_instance_document"

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)

    instance_hostname = sqlalchemy.Column(sqlalchemy.String)

    created_timestamp = sqlalchemy.Column(sqlalchemy.DATETIME)

    requested_do_not_scan = sqlalchemy.Column(sqlalchemy.BOOLEAN, default=False)
    requested_do_not_scan_timestamp = sqlalchemy.Column(sqlalchemy.DATETIME)
    requested_do_not_scan_contact = sqlalchemy.Column(sqlalchemy.String)

    last_scanned_timestamp = sqlalchemy.Column(sqlalchemy.DATETIME)
    last_successful_scanned_timestamp = sqlalchemy.Column(sqlalchemy.DATETIME)
    consecutive_scan_failures = sqlalchemy.Column(sqlalchemy.INTEGER)

    document_updated_timestamp = sqlalchemy.Column(sqlalchemy.DATETIME)
    document_json = sqlalchemy.Column(json_db_type)
    previous_document_json = sqlalchemy.Column(json_db_type)

    latest_description = sqlalchemy.Column(sqlalchemy.String)
    latest_combined_rules = sqlalchemy.Column(sqlalchemy.String)
    latest_accepting_new_users = sqlalchemy.Column(sqlalchemy.BOOLEAN, default=False)
    latest_combined_language_codes = sqlalchemy.Column(sqlalchemy.String)



