import logging
import time

from herd_menu import herd_utils
from herd_menu import herd_orm

import sqlalchemy.orm

engine = sqlalchemy.create_engine('sqlite:///:memory:', echo=False)
Session = sqlalchemy.orm.sessionmaker(bind=engine)
logging.getLogger('sqlalchemy.engine.Engine').setLevel(logging.ERROR)
my_session = Session()

logging.basicConfig(level=logging.DEBUG)

herd_orm.Base.metadata.create_all(engine)

instance_info = herd_utils.get_instance_detail("notpickard.com", my_session)
print(instance_info.last_successful_scanned_timestamp)
print(instance_info.document_json['rules'])
time.sleep(7)
instance_info = herd_utils.get_instance_detail("notpickard.com", my_session)
print(instance_info.last_successful_scanned_timestamp)
print(instance_info.previous_document_json['rules'])
print(instance_info.document_json['rules'])


