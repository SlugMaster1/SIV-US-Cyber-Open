import requests

def get_json_data(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        json_data = response.json()
        return json_data

    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err}")
    except requests.exceptions.Timeout as timeout_err:
        print(f"Timeout error occurred: {timeout_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"An error occurred: {req_err}")

if __name__ == "__main__":
    url = "https://uscybercombine-s4-crypto-sign-compress-encrypt.chals.io/sign_compress_encrypt?data="
    flag = 'SIVUSCG{'
    while True:
      l = len(get_json_data(url + flag + '!')["ciphertext"])
      pc = ''
      for i in range(48,122):
        q = len(get_json_data(url + flag + chr(i))["ciphertext"]) 
        if q < l:
          pc = chr(i)
          break
      else:
        print("Error")
        exit()
      flag += pc
      print(flag)

