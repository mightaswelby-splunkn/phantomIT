"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'verify_script_exists' block
    verify_script_exists(container=container)

    return

def put_restart_script(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('put_restart_script() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'put_restart_script' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['make_directory:artifact:*.cef.vaultId', 'make_directory:artifact:*.cef.sourceHostName', 'make_directory:artifact:*.cef.filePath', 'make_directory:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'put_restart_script' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0] and inputs_item_1[1] and inputs_item_1[2]:
            parameters.append({
                'vault_id': inputs_item_1[0],
                'ip_hostname': inputs_item_1[1],
                'file_destination': inputs_item_1[2],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[3]},
            })

    phantom.act(action="put file", parameters=parameters, assets=['tomcat'], callback=change_permissions, name="put_restart_script", parent_action=action)

    return

def file_exist_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('file_exist_decision() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["verify_script_exists:action_result.status", "!=", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        make_directory(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["verify_script_exists:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        prompt_tomcat_dir(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
create scripts directory
"""
def make_directory(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('make_directory() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'make_directory' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['verify_script_exists:artifact:*.cef.sourceHostName', 'verify_script_exists:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'make_directory' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0]:
            parameters.append({
                'command': "mkdir /opt/scripts/",
                'timeout': 60,
                'ip_hostname': inputs_item_1[0],
                'script_file': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[1]},
            })

    phantom.act(action="execute program", parameters=parameters, assets=['tomcat'], callback=put_restart_script, name="make_directory")

    return

def restart_tomcat_dir(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('restart_tomcat_dir() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'restart_tomcat_dir' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['verify_script_exists:artifact:*.cef.sourceHostName', 'verify_script_exists:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'restart_tomcat_dir' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0]:
            parameters.append({
                'command': "nohup /opt/scripts/tomcat_restart",
                'timeout': 120,
                'ip_hostname': inputs_item_1[0],
                'script_file': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[1]},
            })

    phantom.act(action="execute program", parameters=parameters, assets=['tomcat'], name="restart_tomcat_dir")

    return

def change_permissions(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('change_permissions() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'change_permissions' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['put_restart_script:artifact:*.cef.sourceHostName', 'put_restart_script:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'change_permissions' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0]:
            parameters.append({
                'command': "/usr/bin/chmod +x /opt/scripts/tomcat_restart",
                'timeout': 60,
                'ip_hostname': inputs_item_1[0],
                'script_file': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[1]},
            })

    phantom.act(action="execute program", parameters=parameters, assets=['tomcat'], callback=prompt_tomcat_no_dir, name="change_permissions", parent_action=action)

    return

def verify_script_exists(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('verify_script_exists() called')

    # collect data for 'verify_script_exists' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceHostName', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'verify_script_exists' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'command': "/usr/bin/ls /opt/scripts/tomcat_restart",
                'timeout': 60,
                'ip_hostname': container_item[0],
                'script_file': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="execute program", parameters=parameters, assets=['tomcat'], callback=file_exist_decision, name="verify_script_exists")

    return

def restart_tomcat_no_dir(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('restart_tomcat_no_dir() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'restart_tomcat_no_dir' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['change_permissions:artifact:*.cef.sourceHostName', 'change_permissions:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'restart_tomcat_no_dir' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0]:
            parameters.append({
                'command': "nohup /opt/scripts/tomcat_restart",
                'timeout': 60,
                'ip_hostname': inputs_item_1[0],
                'script_file': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[1]},
            })

    phantom.act(action="execute program", parameters=parameters, assets=['tomcat'], name="restart_tomcat_no_dir")

    return

def prompt_tomcat_dir(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_tomcat_dir() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """Recycling {0} Tomcat JVM"""

    # parameter list for template variable replacement
    parameters = [
        "verify_script_exists:artifact:*.cef.sourceHostName",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=10, name="prompt_tomcat_dir", parameters=parameters, response_types=response_types, callback=format_1)

    return

def prompt_tomcat_no_dir(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_tomcat_no_dir() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """Recycling {0} Tomcat JVM"""

    # parameter list for template variable replacement
    parameters = [
        "change_permissions:artifact:*.cef.sourceHostName",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=10, name="prompt_tomcat_no_dir", parameters=parameters, response_types=response_types, callback=format_2)

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_1() called')
    
    template = """Please approve restart of {0}"""

    # parameter list for template variable replacement
    parameters = [
        "verify_script_exists:artifact:*.cef.sourceHostName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    set_owner_pin_add_tag_add_note_1(container=container)

    return

def set_owner_pin_add_tag_add_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_owner_pin_add_tag_add_note_1() called')

    formatted_data_1 = phantom.get_format_data(name='format_1__as_list')

    phantom.set_owner(container=container, role="Administrator")

    phantom.pin(container=container, data=formatted_data_1, message="Tomcat Recycle", pin_type="card", pin_style="red", name=None)

    phantom.add_tags(container=container, tags="tomcat")

    note_title = "Attention"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    restart_tomcat_dir(container=container)

    return

def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_2() called')
    
    template = """Please approve restart of {0}"""

    # parameter list for template variable replacement
    parameters = [
        "change_permissions:artifact:*.cef.sourceHostName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    set_owner_pin_add_note_2(container=container)

    return

def set_owner_pin_add_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_owner_pin_add_note_2() called')

    formatted_data_1 = phantom.get_format_data(name='format_2__as_list')

    phantom.set_owner(container=container, role="Administrator")

    phantom.pin(container=container, data=formatted_data_1, message="Tomcat Recycle", pin_type="card", pin_style="blue", name=None)

    note_title = "Tomcat OOM errors - Tomcat Recycling"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    restart_tomcat_no_dir(container=container)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return
