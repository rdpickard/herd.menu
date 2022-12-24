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

scan_success = False
instance_info = None

for instance in ["infosec.exchange", "mastodon.social", "hachyderm.io", "circumstances.run", "mstdn.social"]:

    try:
        success, instance_info = herd_utils.get_instance_detail(instance, my_session)
    except ValueError as ve:
        print(ve)
    else:
        print(success)
        if instance_info is not None:
            #print(instance_info.latest_combined_rules)
            #print(instance_info.latest_combined_blocked_domains)
            herd_utils.get_blocked_domains_for_instance_by_name(instance, my_session)
        else:
            print("no instance info")


