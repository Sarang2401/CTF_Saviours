import requests
import json

def get_web_content(url):
    """Fetches content from a URL using GET request."""
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors
        print(f"Successfully fetched {url}")
        print(f"Status Code: {response.status_code}")
        print("\n--- Headers ---")
        for header, value in response.headers.items():
            print(f"{header}: {value}")
        print("\n--- Content (first 500 chars) ---")
        print(response.text[:500])
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return None

def post_data_to_web(url, data, headers=None):
    """Sends POST request with data to a URL."""
    try:
        response = requests.post(url, data=data, headers=headers)
        response.raise_for_status()
        print(f"Successfully posted to {url}")
        print(f"Status Code: {response.status_code}")
        print("\n--- Response Content (first 500 chars) ---")
        print(response.text[:500])
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error posting to {url}: {e}")
        return None

if __name__ == "__main__":
    # Example Usage:
    # Fetch content from a public website
    print("--- Fetching Example.com ---")
    get_web_content("http://example.com")

    # Example of a simple POST request
    print("\n--- Posting to a placeholder API ---")
    test_url = "https://jsonplaceholder.typicode.com/posts"
    post_payload = {
        "title": "foo",
        "body": "bar",
        "userId": 1
    }
    # headers = {"Content-Type": "application/json"} # Often needed for JSON data
    # post_data_to_web(test_url, json.dumps(post_payload), headers=headers)
    post_data_to_web(test_url, post_payload) # requests handles dicts for form data by default