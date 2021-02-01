import networkx
from statements import *
from utils import walk_all_blocks
from hierarchy import NoConcreteDispatch
import copy


class CallGraph:
    """
        Build call graph
    """

    def __init__(self, project, log, framework=None):
        self.project = project
        self.project_classes = copy.copy(self.project.project_classes)
        self.framework_object = framework
        self.log = log
        self.graph = networkx.DiGraph()
        self.build()

    def build(self):
        try:
            for block in walk_all_blocks(self.project_classes):
                method = self.project.blocks_to_methods[block]
                self.graph.add_node(method)
                for stmt in block.statements:
                    if is_invoke(stmt):
                        self._add_invoke(method, block, stmt)
        except:
            print("")

    def _add_invoke(self, container_m, block, invoke):
        is_framework_class = False
        if hasattr(invoke, 'invoke_expr'):
            invoke_expr = invoke.invoke_expr

        else:
            invoke_expr = invoke.right_op

        cls_name = invoke_expr.class_name
        method_name = invoke_expr.method_name
        method_params = invoke_expr.method_params

        if cls_name not in self.project_classes:
            if self.framework_object is None or cls_name not in self.framework_object._project_classes:
            # external classes are currently not supported
                return
        try:
            if cls_name in self.project_classes:
                method = self.project._methods_key[(cls_name, method_name, method_params)]
            else:
                if cls_name in self.framework_object._project_classes:
                    is_framework_class = True
                    method = self.framework_object._methods_key[(cls_name, method_name, method_params)]
        except KeyError as e:
            # TODO should we add a dummy node for "external" methods?
            self.log.warning("Cannot handle call to external method")
            return
            
        try:
            if is_framework_class:
                targets = self.framework_object.get_class_hierarchy().resolve_invoke(invoke_expr, method, container_m, is_framework_class, self.project)
            else:
                targets = self.project.get_class_hierarchy().resolve_invoke(invoke_expr, method, container_m)
        except NoConcreteDispatch as e:
            targets = []
            self.log.warning('Could not resolve concrete dispatch. External method?')

        for target in targets:                
            if target.class_name in self.project_classes:
                self.graph.add_node(target)
                self.graph.add_edge(container_m, target, data=block)

    def next(self, method):
        return self.graph.successors(method)

    def prev(self, method):
        return self.graph.predecessors(method)
