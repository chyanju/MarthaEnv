import copy
import re


class WTGEdge:
    def __init__(self, src_node, dest_node, edge_id, edge_value):
        self.src_node_key = src_node
        self.dest_node_key = dest_node
        self.edge_id = edge_id
        self.edge_value = edge_value
        self.edge_tag = None
        self.event = None
        self.widget = None
        self.handlers = []
        self.stack = []
        self.resource_details = {}
        self.setup()
        self.detect_real_widget_resource()

    def setup(self):
        edge_attributes = self.edge_value.split("\\n")
        for attribute in edge_attributes:
            if 'tag: ' in attribute:
                self.edge_tag = attribute.split("tag: ")[1]

            if 'evt: ' in attribute:
                self.event = attribute.split("evt: ")[1]

            if 'widget: ' in attribute:
                self.widget = attribute.split("widget: ")[1]

            if 'handler: ' in attribute:
                self.handlers = attribute.split("handler: ")[1]

            if 'stack: ' in attribute:
                self.stack = attribute.split("stack: ")[1]

    def get_actionable_resource(self):
        return self.resource_details

    def detect_real_widget_resource(self):
        if self.event == 'implicit_home_event':
            self.resource_details['name'] = 'home'
            self.resource_details['type'] = self.widget.split("[")[1].split("]")[0]
            self.resource_details['action'] = 'click'
            self.resource_details['id'] = 'DEFAULT'

        elif self.event == 'implicit_back_event':
            self.resource_details['name'] = 'back'
            self.resource_details['type'] = self.widget.split("[")[1].split("]")[0]
            self.resource_details['action'] = 'click'
            self.resource_details['id'] = 'DEFAULT'

        elif self.event == 'implicit_power_event':
            self.resource_details['name'] = 'power'
            self.resource_details['type'] = self.widget.split("[")[1].split("]")[0]
            self.resource_details['action'] = 'power_event'
            self.resource_details['id'] = 'DEFAULT'

        elif self.event == 'implicit_rotate_event':
            self.resource_details['name'] = 'rotate'
            self.resource_details['type'] = self.widget.split("[")[1].split("]")[0]
            self.resource_details['action'] = 'shake'
            self.resource_details['id'] = 'DEFAULT'

        elif self.event == 'click':
            self.process_widget()
            self.resource_details['action'] = 'click'

        elif self.event == 'implicit_launch_event':
            self.resource_details['name'] = 'launch'
            self.resource_details['type'] = ''
            self.resource_details['action'] = ''
            self.resource_details['id'] = ''

        else:
            # TODO: we should also consider other events
            pass

    def process_widget(self):
        if self.widget.startswith('INFL'):
            widget_details = self.widget.split("INFL[")[1].split(",")
            self.resource_details['type'] = widget_details[0]

            matched_widget = widget_details[1].split('[', 1)[1].split(']')[0]
            self.resource_details['name'] = matched_widget.split("|")[2]

            if widget_details[1].startswith('AID'):
                self.resource_details['id'] = matched_widget.split("|")[1]

            else:
                self.resource_details['id'] = matched_widget.split("|")[0]

        elif self.widget.startswith('OptionsMenu'):
            self.resource_details['name'] = self.widget.split("[")[1].split("]")[0]
            self.resource_details['type'] = self.widget.split("[")[1].split("]")[0]
            self.resource_details['id'] = 'DEFAULT'

        else:
            self.resource_details['name'] = self.widget.split("[")[0]
            details = self.widget.split("[")[1].split("]")[0]

            if "|" in details:
                items = details.split("|")
                for item in items:
                    if item.startswith("21"):
                        self.resource_details['type'] = item
                    else:
                        if isinstance(item, str):
                            self.resource_details['id'] = item

            else:
                self.resource_details['type'] = details
                self.resource_details['id'] = 'DEFAULT'

    def __str__(self):
        pass
