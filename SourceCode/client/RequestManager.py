import requests
import os

SERVER_PORT = 5100
SERVER_URL = os.getenv("SERVER_URL", f"http://localhost:{SERVER_PORT}")
class RequestManager:
    @staticmethod
    def get_request(endpoint, params=None, success_codes=[200], retry_codes=[], return_data_keys=None):
        """
        Generic GET request handler.

        Args:
            endpoint (str): The API endpoint.
            params (dict, optional): Query parameters.
            success_codes (list): Status codes indicating success.
            retry_codes (list): Status codes indicating the caller should retry.
            return_data_keys (list, optional): Keys to extract from the response data.

        Returns:
            tuple: (should_continue, success, extracted_data)
                - should_continue: True if the caller should retry (e.g., network error or retry code).
                - success: True if the request succeeded.
                - extracted_data: Dict of requested data from the response, or None.
        """
        try:
            response = requests.get(f"{SERVER_URL}/{endpoint}", params=params)
            status_code = response.status_code
            try:
                response_data = response.json()
                message = response_data.get("message", "No message")
            except ValueError:
                message = response.text
                response_data = {}
            if status_code in retry_codes:
                print(message)
                return True, False, None
            elif status_code in success_codes:
                print(message)
                if return_data_keys:
                    extracted_data = {key: response_data.get(key) for key in return_data_keys}
                    return False, True, extracted_data
                return False, True, None
            else:
                print("[ERROR] Server error.")
                return False, False, None
        except requests.exceptions.RequestException as error:
            print(f"[ERROR] Network error: {error}")
            return True, False, None
    
    @staticmethod
    def post_request(endpoint, data=None, files=None, success_codes=[200], retry_codes=[], return_data_keys=None):
        """
        Generic POST request handler.

        Args:
            endpoint (str): The API endpoint.
            data (dict, optional): JSON data to send.
            files (dict, optional): Files to upload.
            success_codes (list): Status codes indicating success.
            retry_codes (list): Status codes indicating the caller should retry.
            return_data_keys (list, optional): Keys to extract from the response data.

        Returns:
            tuple: (should_continue, success, extracted_data)
                - should_continue: True if the caller should retry (e.g., network error or retry code).
                - success: True if the request succeeded.
                - extracted_data: Dict of requested data from the response, or None.
        """
        try:
            if files:
                response = requests.post(f"{SERVER_URL}/{endpoint}", data=data, files=files)
            else:
                response = requests.post(f"{SERVER_URL}/{endpoint}", json=data)
            status_code = response.status_code
            try:
                response_data = response.json()
                message = response_data.get("message", "No message")
            except ValueError:
                message = response.text
                response_data = {}

            if status_code in retry_codes:
                print(message)
                return True, False, None
            elif status_code in success_codes:
                print(message)
                if return_data_keys:
                    extracted_data = {key: response_data.get(key) for key in return_data_keys}
                    return False, True, extracted_data
                return False, True, None
            else:
                print("[ERROR] Server error.")
                return False, False, None
        except requests.exceptions.RequestException as error:
            print(f"[ERROR] Network error: {error}")
            return True, False, None