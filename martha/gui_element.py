class GuiElement:
    def __init__(self, node):
        self.node = node
        self.attributes = {}

        self.index = None
        self.text = None
        self.resource_id = None
        self.class_name = None
        self.package = None
        self.content_desc = None
        self.checkable = None
        self.checked = None
        self.clickable = None
        self.enabled = None
        self.focusable = None
        self.focused = None
        self.scrollable = None
        self.long_clickable = None
        self.password = None
        self.selected = None
        self.visible_to_user = None
        self.bounds = None
        self.parsed_bounds = None
        self.x = None
        self.y = None
        self.setup()
        self.element_summary = ''
        self.compute_coordinate()
        self.compute_gui_element_summary()

    def setup(self):
        for item in self.node.items():
            key = item[0]
            value = item[1]
            self.attributes[key] = value
            if key == 'bounds':
                self.bounds = value
            elif key == 'index':
                self.index = value
            elif key == 'text':
                self.text = value
            elif key == 'resource-id':
                self.resource_id = value
            elif key == 'class':
                self.class_name = value
            elif key == 'package':
                self.package = value
            elif key == 'content-desc':
                self.content_desc = value
            elif key == 'checkable':
                self.checkable = value
            elif key == 'checked':
                self.checked = value
            elif key == 'clickable':
                self.clickable = value
            elif key == 'enabled':
                self.enabled = value
            elif key == 'focusable':
                self.focusable = value
            elif key == 'focused':
                self.focused = value
            elif key == 'scrollable':
                self.scrollable = value
            elif key == 'long-clickable':
                self.long_clickable = value
            elif key == 'password':
                self.password = value
            elif key == 'selected':
                self.selected = value
            elif key == 'visible-to-user':
                self.visible_to_user = value
            else:
                pass

        # parse bounds
        self.parsed_bounds = eval(self.bounds.replace("][",","))
        self.attributes["parsed_bounds"] = self.parsed_bounds

    def compute_coordinate(self):
        left = self.bounds.split('][')[0]
        right = self.bounds.split('][')[1]
        first = left.split("[")[1].split(',')
        second = right.split(']')[0].split(',')
        self.x = int((int(first[0]) + int(second[0]))/2)
        self.y = int((int(first[1]) + int(second[1])) / 2)

    def compute_gui_element_summary(self):
        root_child = self.node
        bfs_queue = []
        bfs_queue.append(root_child)
        all_tokens = []

        while len(bfs_queue) != 0:
            top_element = bfs_queue.pop()
            # children = top_element.getchildren()
            children = list(top_element)
            bfs_queue.extend(children)

            for item in top_element.items():
                all_tokens.append(item[1])

        self.element_summary = " : ".join(all_tokens)



