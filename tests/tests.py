"""
Script description: This script imports tests the Streamlit-Authenticator package. 

Libraries imported:
-------------------
- streamlit: Framework used to build pure Python web applications.
"""

from streamlit.testing.v1 import AppTest

def test_login():
    at = AppTest.from_file('app.py').run()
    at.text_input[0].input('test').run()
    at.text_input[1].input('ABCdef123$$').run()
    at.button[0].click().run()
    assert 'jsmith' in at.session_state['username']
