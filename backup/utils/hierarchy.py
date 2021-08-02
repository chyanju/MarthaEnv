#import IPython
import sys
import os
from statements import *
import copy

def debug():
    # Ref: https://stackoverflow.com/a/1278740
    exc_type, exc_obj, exc_tb = sys.exc_info()
    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
    print(exc_type, fname, exc_tb.tb_lineno)
    print(traceback.format_exc())


'''      try:
            print(self.sub_interfaces.aa)
        except Exception as e:
            IPython.embed()
'''

class HierarchyError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class NoConcreteDispatch(HierarchyError):
    def __init__(self, msg):
        self.msg = msg


# TODO: How to deal with external packages?
# cls.super_class
# KeyError: u'com.google.protobuf.GeneratedMessageV3'
class Hierarchy:
    """
        This class deals with classes hierachy to address dynamic invokes
    """

    def __init__(self, project):
        self.project_classes = copy.copy(project.project_classes)

        if hasattr(project, "_support_classes"):
            self.project_classes.update(project._support_classes)
        if hasattr(project, "_all_cls"):
            self.project_classes = copy.copy(project._all_cls)

        self.interface_implementers = {}
        self.sub_interfaces = {}
        self.dir_sub_interfaces = {}
        self.sub_classes = {}
        self.dir_sub_classes = {}
        # init data
        self.init_hierarchy()
  
    def init_hierarchy(self):
        for class_name, cls in self.project_classes.items():
            # resolvingLevel?
            if 'INTERFACE' in cls.attrs:
                self.interface_implementers[cls] = []
                self.dir_sub_interfaces[cls] = []
            else:
                self.dir_sub_classes[cls] = []

        for class_name, cls in self.project_classes.items():

            # This check should mean that whether the class has any super class or any super interfaces
            if self.has_super_class(cls):

                if 'INTERFACE' in cls.attrs:
                    # TODO
                    # super_interfaces
                    pass

                else:
                    # So an anomymous class may have no super classes or an external super classes
                    # but it can implement an interface. So we need to keep the first two statement within try
                    # such that if the class does not have any super class or extends some external class
                    # we should not bother to update the dir_sub_classes but we should also check whether it has implemented
                    # any interface and accordingly we should add this class to the list of implementers for that interface 
                    try:
                        super_class = self.project_classes[cls.super_class]
                        self.dir_sub_classes[super_class].append(cls)
                    except KeyError:
                        pass

                    for i_name in cls.interfaces:
                        # get interface
                        if i_name not in self.project_classes:
                            continue
                        i = self.project_classes[i_name]
                        self.interface_implementers[i].append(cls)

        # fill direct implementers with subclasses
        for class_name, cls in self.project_classes.items():
            if 'INTERFACE' in cls.attrs:
                implementers = self.interface_implementers[cls]
                s = set()

                for c in implementers:
                    s |= set(self.get_sub_classes_including(c))

                self.interface_implementers[cls] = list(s)

    def has_super_class(self, cls):
        if cls.super_class:
            try:
                self.project_classes[cls.super_class]
                return True
            except KeyError:
                pass
        # A class may have no super class or some external class as a super class
        # but it can implement an interface. This is the case with anonymous classes
        # So we should add this check otherwise we may incorrectly miss the implementer of
        # some of the intrerfaces
        if cls.interfaces:
            return True       
        return False

    def is_subclass_including(self, cls_child, cls_parent):
        parent_classes = self.get_super_classes_including(cls_child)

        if cls_parent in parent_classes:
            return True

        # FIXME
        # for cls in parent_classes:
        #     if is_phatom(cls):
        #         return True

        return False

    def is_subclass(self, cls_child, cls_parent):
        parent_classes = self.get_super_classes(cls_child)

        if cls_parent in parent_classes:
            return True

        # FIXME
        # for cls in parent_classes:
        #     if is_phatom(cls):
        #         return True

        return False

    def is_visible_method(self, cls, method):
        method_cls = self.project_classes[method.class_name]

        if not self.is_visible_class(cls, method_cls):
            return False

        if 'PUBLIC' in method.attrs:
            return True

        if 'PRIVATE' in method.attrs:
            return cls == method_cls

        # package visibility
        # FIXME
        package_from = cls.name.split('.')[:-1]
        package_to = method_cls.name.split('.')[:-1]

        if 'PROTECTED' in method.attrs:
            is_sub = self.is_subclass_including(cls, method_cls)
            is_same_package = package_from == package_to
            return is_sub or is_same_package

        return package_from == package_to

    def is_visible_class(self, cls_from, cls_to):
        if 'PUBLIC' in cls_to.attrs:
            return True

        if 'PROTECTED' in cls_to.attrs or 'PRIVATE' in cls_to.attrs:
            return False

        # package visibility
        # FIXME
        package_from = cls_from.name.split('.')[:-1]
        package_to = cls_to.name.split('.')[:-1]
        return package_from == package_to

    def get_super_classes(self, cls):
        if 'INTERFACE' in cls.attrs:
            raise HierarchyError('This is an Interface')

        super_classes = []

        current = cls
        try:
            while True:
                current = self.project_classes[current.super_class]
                super_classes.append(current)

        except KeyError:
            return super_classes

    def get_super_classes_including(self, cls):
        super_classes = self.get_super_classes(cls)
        res = []

        res.append(cls)
        res.extend(super_classes)

        return res

    def get_implementers(self, interface):
        if 'INTERFACE' not in interface.attrs:
            raise HierarchyError('This is not an interface')

        res_set = set()

        for i in self.get_sub_interfaces_including(interface):
            res_set |= set(self.interface_implementers[i])

        return list(res_set)

    def get_sub_interfaces_including(self, interface):
        res = self.get_sub_interfaces(interface)
        res.append(interface)

        return res

    def get_sub_interfaces(self, interface):
        if 'INTERFACE' not in interface.attrs:
            raise HierarchyError('This is not an interface')

        if interface in self.sub_interfaces:
            return self.sub_interfaces[interface]

        # Otherwise
        res = []
        for i in self.dir_sub_interfaces[interface]:
            res.extend(self.get_sub_interfaces_including(i))

        self.sub_interfaces[interface] = res
        return res

    def get_sub_classes(self, cls):
        if 'INTERFACE' in cls.attrs:
            raise HierarchyError('This is an Interface. Class needed')

        if cls in self.sub_classes:
            return self.sub_classes[cls]

        res = []
        for c in self.dir_sub_classes[cls]:
            # resolving level > HIERACHY?
            res.extend(self.get_sub_classes_including(c))

        self.sub_classes[cls] = res
        return res

    def get_sub_classes_including(self, cls):
        if 'INTERFACE' in cls.attrs:
            raise HierarchyError('This is an Interface. Class needed')

        res = []
        res.extend(self.get_sub_classes(cls))
        res.append(cls)

        return res

    def resolve_abstract_dispatch(self, cls, method):
        if 'INTERFACE' in cls.attrs:
            classes_set = set()
            for i in self.get_implementers(cls):
                classes_set |= set(self.get_sub_classes_including(i))
            classes = list(classes_set)
        else:
            classes = self.get_sub_classes_including(cls)

        res_set = set()
        for c in classes:
            if 'ABSTRACT' not in c.attrs:
                res_set.add(self.resolve_concrete_dispatch(c, method))

        return list(res_set)

    def resolve_concrete_dispatch(self, cls, method):
        if 'INTERFACE' in cls.attrs:
            raise HierarchyError('class needed!')

        for c in self.get_super_classes_including(cls):
            for m in c.methods:
                if m.name == method.name and m.params == method.params:
                    if self.is_visible_method(c, method):
                        return m

        raise NoConcreteDispatch('Could not resolve concrete dispatch!')

    def resolve_special_dispatch(self, method, container, project=None):
        # container is the method that contains the invoke
        method_cls = self.project_classes[method.class_name]
        
        if project is None:
            container_cls = self.project_classes[container.class_name]
        else:
            container_cls = project.project_classes[container.class_name]

        if 'PRIVATE' in method.attrs:
            return method

        elif method.name == '<init>':
            return method

        # From java8 a default of static method can be defined within an interface
        # the target method class can be an interface also. Therefore, we need to return the method
        # if the method_cls is an interface rather than raising an hierarchy error
        elif 'INTERFACE' in method_cls.attrs:
            return method
        elif self.is_subclass(method_cls, container_cls) and project is None:
            return self.resolve_concrete_dispatch(container_cls, method)

        else:
            return method

    # Generic method to resolve invoke
    # Given an invoke expression it figures out which "technique" should apply
    def resolve_invoke(self, invoke_expr, method, container, is_framework=False, project=None):
        invoke_type = str(type(invoke_expr))
        cls = self.project_classes[method.class_name]

        if 'VirtualInvokeExpr' in invoke_type:
            targets = self.resolve_abstract_dispatch(cls, method)

        elif 'DynamicInvokeExpr' in invoke_type:
            targets = self.resolve_abstract_dispatch(cls, method)

        elif 'InterfaceInvokeExpr' in invoke_type:
            targets = self.resolve_abstract_dispatch(cls, method)

        elif 'SpecialInvokeExpr' in invoke_type:
            if is_framework == False:
                t = self.resolve_special_dispatch(method, container)
            else:
                t = self.resolve_special_dispatch(method, container, project)
            
            targets = [t]

        elif 'StaticInvokeExpr' in invoke_type:
            targets = [method]

        return targets
