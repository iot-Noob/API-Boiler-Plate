from fastapi import APIRouter, Depends, HTTPException, Query,Response
from fastapi.responses import JSONResponse
 
from App.Security import *
from Models.model import *
 
import os
import dotenv
import shutil
import asyncio
 
from typing import Optional
import logging