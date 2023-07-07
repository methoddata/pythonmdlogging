import json
import logging
import os
import re
import requests
from io import StringIO

class MDLogger:
    def __init__(self, serviceName, provider, projectname, loggingLevel = "WARN",requestPayload = None, logFormat = '%(asctime)s - %(levelname)s - %(message)s') -> None:
        '''
        serviceName - Name of the function
        requestPayload - The request for Event-Driven functions
        provider - Hosting service, eg. AWS, Azure, Local
        projectName - Name of the project     
        logFormat - logging format - default: '%(asctime)s - %(levelname)s - %(message)s'
        debugLevel - DEBUG,INFO, WARN, ERROR: default - WARN
        '''
        cLoggingLevel = logging.WARN
        if loggingLevel == "INFO":
            cLoggingLevel = logging.INFO
        if loggingLevel == "DEBUG":
            cLoggingLevel = logging.DEBUG
        if loggingLevel == "ERROR":
            cLoggingLevel = logging.ERROR

        if len(logging.getLogger().handlers) > 0:
            self.logger = logging.getLogger()
        else:
            logging.basicConfig(format=logFormat,
                datefmt='%Y-%m-%d:%H:%M:%S',
                level=cLoggingLevel)
            self.logger = logging.getLogger()
        self.logger.setLevel(cLoggingLevel)
        self.log_string = StringIO()
        handler = logging.StreamHandler(self.log_string)
        handler.setLevel(logging.WARN)
        handler.setFormatter(logging.Formatter('%(message)s',
                datefmt='%Y-%m-%d:%H:%M:%S'))
        self.logger.addHandler(handler)
        self.isActive = False
        self.requestPayload = requestPayload
        self.serviceName = serviceName
        self.provider = provider
        self.projectName = projectname
        self.loggingBearer = os.getenv('loggingBearer', None)
        self.loggingEndpoint = os.getenv('loggingEndpoint', None)
        self.loggingStage = os.getenv('loggingStage', "dev")

        if self.loggingBearer is None:
            self.logger.warn("No Logging Authenticaion Token Found")
        if self.loggingEndpoint is None:
            self.logger.warn("No Logging Endpoint Found")
        if self.serviceName is None:
            self.logger.warn("No Service Name Found")
        if self.provider is None:
            self.logger.warn("No Provider Found")
        if self.projectName is None:
            self.logger.warn("No Project Name Found")

        if (self.projectName is not None) and (self.provider is not None) and (self.serviceName is not None) and (self.loggingEndpoint is not None) and (self.loggingBearer is not None):
            logging.info("Logger Configuration found")
            self.isActive = True

    def exception(self, message = ""):
        '''
        Use in a try/catch block
        message - Logging Message, Excluding traceback
        request - (Optional) The request that caused the exception
        '''
        try:
            self.logger.exception(message)
            tracebackstring = self.log_string.getvalue()
            pattern = r'File "(.*)",'
            match = re.search(pattern, tracebackstring)
            if match:
                file_path = match.group(1)
                file_directory = os.path.dirname(file_path)
                cleaned_traceback = tracebackstring.replace(file_directory, '')
                cleaned_traceback = cleaned_traceback.replace("Traceback (most recent call last):", '')
            else:
                cleaned_traceback = tracebackstring
            if cleaned_traceback == "NoneType: None":
                cleaned_traceback = "No Traceback Found"

            if self.isActive == False:
                self.logger.warn(f"Logger Configuration not Found")
                return None
            data = {
                "serviceName": self.serviceName,
                "message": f"Message: {message} - {cleaned_traceback}",
                "provider": self.provider,
                "projectName": self.projectName,
                "loggingLevel": "ERROR",
                "stage": self.loggingStage
            } 
            if self.requestPayload is not None:
                data.update({"requestPayload": self.requestPayload})
            
            self.__SendMessage(data=data)

        except Exception as e:
            logging.exception("An Error Occured while sending email")

    def error(self, message):
        '''
        message - Logging Message, include traceback for errors
        request - Optional
        '''
        try:
            self.logger.error(f"Message: {message}")
            if self.isActive == False:
                self.logger.warn(f"Logger Configuration not Found")
                return None
            
            data = {
                "serviceName": self.serviceName,
                "message": message,
                "provider": self.provider,
                "projectName": self.projectName,
                "loggingLevel": "ERROR",
                "stage": self.loggingStage
            } 

            if self.requestPayload is not None:
                data.update({"requestPayload": self.requestPayload})

            self.__SendMessage(data=data)

        except Exception as e:
            logging.exception("An Error Occured while sending email")

    def warn(self, message):
        '''
        message - Logging Message, include traceback for errors
        request - Optional
        '''
        try:
            self.logger.warn(f"Message: {message}")
            if self.isActive == False:
                self.logger.warn(f"Logger Configuration not Found")
                return None
            
            data = {
                "serviceName": self.serviceName,
                "message": message,
                "provider": self.provider,
                "projectName": self.projectName,
                "loggingLevel": "WARN",
                "stage": self.loggingStage
            } 

            #if self.requestPayload is not None:
            #    data.update({"requestPayload": self.requestPayload})
            
            self.__SendMessage(data=data)
        

        except Exception as e:
            logging.exception("An Error Occured while sending email")

    def info(self, message):
        '''
        message - Logging Message, include traceback for errors
        request - Optional
        '''
        try:
            self.logger.info(f"Message: {message}")
            if self.isActive == False:
                self.logger.warn(f"Logger Configuration not Found")
                return None
            
        except Exception as e:
            logging.exception("An Error Occured while sending email")

    def __SendMessage(self, data):
        try:
            header = {
                    "x-api-key": f"{self.loggingBearer}",
                    "Content-Type": "application/json"
                }
            response : requests.Response= requests.post(url=self.loggingEndpoint, data= json.dumps(data), headers=header)
            if response.status_code == 200:
                logging.info("Message Succesfully Sent")
                return True
            else:
                logging.warn(f"Could not send message: {response.status_code}, Response: {response.text}")
                return False
        except Exception as e:
            logging.exception("An Error Occured while sending Log")

