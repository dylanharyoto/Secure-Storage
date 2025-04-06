import requests
class RequestManager:
    @staticmethod
    def post_request(SERVER_URL, endpoint, data=None, files=None):
        """
        Generic function to make a POST request to the server.
        
        Args:
            endpoint (str): The API endpoint (e.g., "check_username").
            data (dict, optional): JSON data to send in the request body.
            files (dict, optional): Files to upload with the request.
        
        Returns:
            tuple: (status_code, response_data) or (None, None) on network error.
        """
        url = f"{SERVER_URL}/{endpoint}"
        try:
            if files:
                response = requests.post(url, data=data, files=files)
            else:
                response = requests.post(url, json=data)
            status_code = response.status_code
            try:
                response_data = response.json()
            except ValueError:
                response_data = {"message": response.text}
            return status_code, response_data
        except requests.exceptions.RequestException as error:
            print(f"[ERROR] Network error: {error}")
            return None, None
    
    @staticmethod
    def get_request(SERVER_URL, endpoint, params=None):
        """
        Generic function to make a GET request to the server.
        
        Args:
            endpoint (str): The API endpoint (e.g., "get_files").
            params (dict, optional): Query parameters to include in the request.
        
        Returns:
            tuple: (status_code, response_data) or (None, None) on network error.
        """
        url = f"{SERVER_URL}/{endpoint}"
        try:
            response = requests.get(url, params=params)
            status_code = response.status_code
            try:
                response_data = response.json()
            except ValueError:
                response_data = {"message": response.text}
            return status_code, response_data
        except requests.exceptions.RequestException as error:
            print(f"[ERROR] Network error: {error}")
            return None, None