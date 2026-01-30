from bs4 import BeautifulSoup
import requests


def extract_forms(page_url):
    forms = []

    try:
        response = requests.get(page_url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        for form in soup.find_all("form"):
            form_data = {
                "action": form.get("action", ""),
                "method": form.get("method", "get").lower(),
                "inputs": []
            }

            for input_tag in form.find_all("input"):
                name = input_tag.get("name")
                if name:
                    form_data["inputs"].append({"name": name})

            forms.append(form_data)
    except requests.RequestException:
        pass

    return form


def print_banner():

    banner = r"""
    ========================================================
      _____                      _____                      _   
     |  _  |                    /  ___|                    | |  
     | |_| | _ __    ___ __  __ \ `--.   ___  ___   _   _  | |_ 
     |  _  || '_ \  / _ \\ \/ /  `--. \ / __|/ _ \ | | | | | __|
     | | | || |_) ||  __/ >  <  /\__/ /| (__| (_) || |_| | | |_ 
     \_| |_/| .__/  \___|/_/\_\ \____/  \___|\___/  \__,_|  \__|
            | |                                                 
            |_|         [Version 1.0 @Monark ]
    ========================================================
    """
    print(banner, flush=True)