from langchain_community.chat_models import ChatLlamaCpp
from langchain.agents import create_agent
from langchain.tools import tool
from langchain_core.output_parsers import StrOutputParser,JsonOutputKeyToolsParser
from langchain_postgres import PostgresChatMessageHistory,PGEngine
from langchain_community.chat_message_histories import ChatMessageHistory
from langchain_core.runnables import RouterInput,RunnableWithMessageHistory,RunnableParallel,Runnable,RouterRunnable,RunnableBranch,RunnablePick
from  langchain_core.prompts import ChatPromptTemplate,PromptTemplate,MessagesPlaceholder
from langchain_core.messages import SystemMessage,HumanMessage,AIMessage
import os
import gc
import ctypes
import os
from pathlib import Path
class Lc_Connector:
    def __init__(self,model_path:Path):
        pass