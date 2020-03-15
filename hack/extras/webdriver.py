from selenium.webdriver.common.by import By
from selenium import webdriver
import unittest

class WebKitFeatureStatusTest(unittest.TestCase):

    def test_feature_status_page_search(self):
        self.driver.get("https://webkit.org/status/")

        # Enter "CSS" into the search box.
        search_box = self.driver.find_element_by_id("search")
        search_box.send_keys("CSS")
        value = search_box.get_attribute("value")
        self.assertTrue(len(value) > 0)
        search_box.submit()

        # Count the results.
        feature_count = self.shown_feature_count()
        self.assertTrue(len(feature_count) > 0)

    def test_feature_status_page_filters(self):
        self.driver.get("https://webkit.org/status/")

        filters = self.driver.find_element(By.CSS_SELECTOR, "ul#status-filters li input[type=checkbox]")
        self.assertTrue(len(filters) is 7)

        # Make sure every filter is turned off.
        for checked_filter in filter(lambda f: f.is_selected(), filters):
            checked_filter.click()

        # Count up the number of items shown when each filter is checked.
        unfiltered_count = self.shown_feature_count()
        running_count = 0
        for filt in filters:
            filt.click()
            self.assertTrue(filt.is_selected())
            running_count += self.shown_feature_count()
            filt.click()

        self.assertTrue(running_count is unfiltered_count)

    def shown_feature_count(self):
        return len(self.driver.execute_script("return document.querySelectorAll('li.feature:not(.is-hidden)')"))

    def setup_module(module):
        WebKitFeatureStatusTest.driver = webdriver.Safari()

    def teardown_module(module):
        WebKitFeatureStatusTest.driver.quit()

if __name__ == '__main__':
    unittest.main()