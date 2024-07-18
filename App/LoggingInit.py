import logging
import os
from App.GetEnvDate import log_path

if log_path:
    lop=os.path.join(log_path,"logs.log")
else:
    lop="userlog/logs.log"
if not os.path.exists(log_path):
    os.makedirs(log_path)
logging.basicConfig(filename=lop,filemode='a', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.DEBUG)