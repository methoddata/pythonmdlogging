import importlib
import inspect
import json
import logging
import os
import re
import warnings
from functools import wraps
from io import StringIO
from typing import Any, Callable, Dict, Optional

import requests
from opentelemetry import context, trace
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from opentelemetry.util.types import AttributeValue as SpanAttributeValue
from pydantic import BaseSettings

global_tracer_provider: Optional[object] = None
tracer_providers_by_service_name: Dict[str, object] = {}
span_processors = []


class MDLogger:
    def __init__(
        self,
        serviceName,
        provider,
        projectname,
        loggingLevel="WARN",
        requestPayload=None,
        logFormat="%(asctime)s - %(levelname)s - %(message)s",
    ) -> None:
        """
        serviceName - Name of the function
        requestPayload - The request for Event-Driven functions
        provider - Hosting service, eg. AWS, Azure, Local
        projectName - Name of the project
        logFormat - logging format - default: '%(asctime)s - %(levelname)s - %(message)s'
        debugLevel - DEBUG,INFO, WARN, ERROR: default - WARN
        """
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
            logging.basicConfig(
                format=logFormat, datefmt="%Y-%m-%d:%H:%M:%S", level=cLoggingLevel
            )
            self.logger = logging.getLogger()
        self.logger.setLevel(cLoggingLevel)
        self.log_string = StringIO()
        handler = logging.StreamHandler(self.log_string)
        handler.setLevel(logging.WARN)
        handler.setFormatter(
            logging.Formatter("%(message)s", datefmt="%Y-%m-%d:%H:%M:%S")
        )
        self.logger.addHandler(handler)
        self.isActive = False
        self.requestPayload = requestPayload
        self.serviceName = serviceName
        self.provider = provider
        self.projectName = projectname
        self.loggingBearer = os.getenv("loggingBearer", None)
        self.loggingEndpoint = os.getenv("loggingEndpoint", None)
        self.loggingStage = os.getenv("loggingStage", "dev")

        if self.loggingBearer is None:
            self.logger.warning("No Logging Authenticaion Token Found")
        if self.loggingEndpoint is None:
            self.logger.warning("No Logging Endpoint Found")
        if self.serviceName is None:
            self.logger.warning("No Service Name Found")
        if self.provider is None:
            self.logger.warning("No Provider Found")
        if self.projectName is None:
            self.logger.warning("No Project Name Found")

        if (
            (self.projectName is not None)
            and (self.provider is not None)
            and (self.serviceName is not None)
            and (self.loggingEndpoint is not None)
            and (self.loggingBearer is not None)
        ):
            logging.info("Logger Configuration found")
            self.isActive = True
        else:
            logging.info("Logger Configuration not found")

    def exception(self, message="", exception=None):
        """
        Use in a try/catch block
        message - Logging Message, Excluding traceback
        request - (Optional) The request that caused the exception
        """
        try:
            self.logger.exception(message)
            tracebackstring = self.log_string.getvalue()
            pattern = r'File "(.*)",'
            match = re.search(pattern, tracebackstring)
            if match:
                file_path = match.group(1)
                file_directory = os.path.dirname(file_path)
                cleaned_traceback = tracebackstring.replace(file_directory, "")
                cleaned_traceback = cleaned_traceback.replace(
                    "Traceback (most recent call last):", ""
                )
            else:
                cleaned_traceback = tracebackstring
            if cleaned_traceback == "NoneType: None":
                cleaned_traceback = "No Traceback Found"
            current_span = trace.get_current_span()

            if current_span is not None:
                span_context = current_span.get_span_context()
                if span_context is not None:
                    current_span.add_event(
                        f"EXCEPTION: {message} - {cleaned_traceback}"
                    )
                    if exception is not None:
                        current_span.record_exception(exception)
                        current_span.set_status(
                            trace.Status(
                                trace.StatusCode.ERROR,
                                str({message} - {cleaned_traceback}),
                            )
                        )
                    else:
                        current_span.set_status(
                            trace.Status(
                                trace.StatusCode.ERROR,
                                str({message} - {cleaned_traceback}),
                            )
                        )
                    current_span.set_attribute("Exception", str(message))
                    current_span.set_attribute("Project Name", str(self.projectName))
                    current_span.set_attribute("Service Name", str(self.serviceName))
                    current_span.set_attribute("Stage", str(self.loggingStage))
                    current_span.set_attribute("Provider", str(self.provider))
            if self.isActive is False:
                return None
            data = {
                "serviceName": self.serviceName,
                "message": f"Message: {message} - {cleaned_traceback}",
                "provider": self.provider,
                "projectName": self.projectName,
                "loggingLevel": "ERROR",
                "stage": self.loggingStage,
            }
            if self.requestPayload is not None:
                data.update({"requestPayload": self.requestPayload})

            self.__SendMessage(data=data)

        except Exception as e:
            logging.exception("An Error Occured while sending email")

    def error(self, message):
        """
        message - Logging Message, include traceback for errors
        request - Optional
        """
        try:
            current_span = trace.get_current_span()

            if current_span is not None:
                span_context = current_span.get_span_context()
                if span_context is not None:
                    current_span.add_event(f"ERROR: {message}")
                    current_span.set_status(
                        trace.Status(trace.StatusCode.ERROR, str(message))
                    )
                    current_span.set_attribute("ERROR", str(message))
                    current_span.set_attribute("Project Name", str(self.projectName))
                    current_span.set_attribute("Service Name", str(self.serviceName))
                    current_span.set_attribute("Stage", str(self.loggingStage))
                    current_span.set_attribute("Provider", str(self.provider))
            self.logger.error(f"Message: {message}")
            if self.isActive is False:
                return None

            data = {
                "serviceName": self.serviceName,
                "message": message,
                "provider": self.provider,
                "projectName": self.projectName,
                "loggingLevel": "ERROR",
                "stage": self.loggingStage,
            }

            if self.requestPayload is not None:
                data.update({"requestPayload": self.requestPayload})

            self.__SendMessage(data=data)

        except Exception as e:
            logging.exception("An Error Occured while sending email")

    def warn(self, message):
        """
        message - Logging Message, include traceback for errors
        request - Optional
        """
        try:
            current_span = trace.get_current_span()

            if current_span is not None:
                span_context = current_span.get_span_context()
                if span_context is not None:
                    current_span.add_event(f"WARN: {message}")
                    current_span.set_attribute("Warning", str(message))
                    current_span.set_attribute("Project Name", str(self.projectName))
                    current_span.set_attribute("Service Name", str(self.serviceName))
                    current_span.set_attribute("Stage", str(self.loggingStage))
                    current_span.set_attribute("Provider", str(self.provider))
                    current_span.set_status(
                        trace.Status(trace.StatusCode.ERROR, str(message))
                    )
            self.logger.warning(f"Message: {message}")
            if self.isActive is False:
                return None

            data = {
                "serviceName": self.serviceName,
                "message": message,
                "provider": self.provider,
                "projectName": self.projectName,
                "loggingLevel": "WARN",
                "stage": self.loggingStage,
            }

            # if self.requestPayload is not None:
            #    data.update({"requestPayload": self.requestPayload})

            self.__SendMessage(data=data)

        except Exception as e:
            logging.exception("An Error Occured while sending email")

    def info(self, message):
        """
        message - Logging Message, include traceback for errors
        request - Optional
        """
        try:
            current_span = trace.get_current_span()

            if current_span is not None:
                span_context = current_span.get_span_context()
                if span_context is not None:
                    current_span.add_event(f"INFO: {message}")
                    current_span.set_attribute("Info", str(message))
                    current_span.set_attribute("Project Name", str(self.projectName))
                    current_span.set_attribute("Service Name", str(self.serviceName))
                    current_span.set_attribute("Stage", str(self.loggingStage))
                    current_span.set_attribute("Provider", str(self.provider))

            self.logger.info(f"Message: {message}")
            if self.isActive is False:
                return None

        except Exception as e:
            logging.exception("An Error Occured while sending email")

    def __SendMessage(self, data):
        try:
            header = {
                "x-api-key": f"{self.loggingBearer}",
                "Content-Type": "application/json",
            }
            response: requests.Response = requests.post(
                url=self.loggingEndpoint, data=json.dumps(data), headers=header
            )
            if response.status_code == 200:
                logging.info("Message Succesfully Sent")
                return True
            else:
                logging.warning(
                    f"Could not send message: {response.status_code}, Response: {response.text}"
                )
                return False
        except Exception as e:
            logging.exception("An Error Occured while sending Log")


def get_tracer(module_name: str, service_name: str = None):
    """
    Get the `Tracer` for the specified module and service name
    Args:
        module_name: module name
        service_name: optional service name

    Returns: a Tracer object

    """
    global global_tracer_provider, tracer_providers_by_service_name
    tracer_provider = (
        global_tracer_provider
        if service_name is None
        else tracer_providers_by_service_name.get(service_name)
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return trace.get_tracer(module_name, tracer_provider=tracer_provider)


class __MDInstrumented:
    def __init__(
        self,
        span_name,
        service_name,
        span_attributes: Optional[Dict[str, SpanAttributeValue]],
    ) -> None:
        self.span_name = span_name
        self.service_name = service_name
        self.span_attributes = span_attributes if span_attributes is not None else {}

    def __call__(self, wrapped_function: Callable) -> Callable:
        module = inspect.getmodule(wrapped_function)
        is_async = inspect.iscoroutinefunction(wrapped_function)
        module_name = __name__
        if module is not None:
            module_name = module.__name__
        span_name = self.span_name or wrapped_function.__qualname__

        @wraps(wrapped_function)
        def new_f(*args, **kwargs):
            with get_tracer(
                module_name, service_name=self.service_name
            ).start_as_current_span(span_name) as span:
                span.set_attributes(self.span_attributes)
                return wrapped_function(*args, **kwargs)

        @wraps(wrapped_function)
        async def new_f_async(*args, **kwargs):
            with get_tracer(
                module_name, service_name=self.service_name
            ).start_as_current_span(span_name) as span:
                span.set_attributes(self.span_attributes)
                return await wrapped_function(*args, **kwargs)

        return new_f_async if is_async else new_f


def MDinstrumented(
    wrapped_function: Optional[Callable] = None,
    *,
    span_name: Optional[str] = None,
    service_name: Optional[str] = None,
    span_attributes: Optional[Dict[str, SpanAttributeValue]] = None,
) -> Any:
    """
    Decorator to enable opentelemetry instrumentation on a function.

    When the decorator is used, a child span will be created in the current trace
    context, using the fully-qualified function name as the span name.
    Alternatively, the span name can be set manually by setting the span_name parameter

    @param wrapped_function:  function or method to wrap
    @param span_name:  optional span name.  Defaults to fully qualified function name of wrapped function
    @param service_name: optional service name.  Defaults to service name set in first invocation
                         of `init_telemetry_provider`
    @param span_attributes: optional dictionary of attributes to be set on the span
    """
    inst = __MDInstrumented(
        span_name=span_name,
        service_name=service_name,
        span_attributes=span_attributes,
    )
    if wrapped_function:
        return inst(wrapped_function)
    return inst
