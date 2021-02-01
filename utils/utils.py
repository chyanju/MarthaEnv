import pydot as pydot
import networkx
#import IPython
import os

"""
    Utils functions
"""


def get_method_key(method):
    return (method.class_name, method.name, method.params)


def same_method_signature(method1, method2):
    return method1.name == method2.name and method1.params == method2.params


def walk_all_statements(classes, methods=None):
    for class_name, cls in classes.items():
        for method in cls.methods:
            if methods is not None and method not in methods:
                continue

            for block in method.blocks:
                for stmt in block.statements:
                    yield stmt


def walk_all_blocks(classes, methods=None):
    for class_name, cls in classes.items():
        for method in cls.methods:
            if methods is not None and method not in methods:
                continue
            for block in method.blocks:
                yield block

def add_graph_edges(src_node, dest_node, graph, edge_label=None):
    graph.add_edge(src_node, dest_node)

def has_predecessor(graph, node):
    predecessors = graph.predecessors(node)
    count = 0

    for pred in predecessors:
        count = count + 1

    if count == 0:
        return False
    else:
        return True

def print_graph(graph_dir, apk_name, graph, name=''):
    content = ''
    # Ref: https://stackoverflow.com/questions/33722809/nx-write-dot-generates-redundant-nodes-when-input-nodes-have-a-colon
    dot_file_name = apk_name + name + ".dot"
    dot_file_path = os.path.join(graph_dir, dot_file_name)
    
    with open(dot_file_path, 'w', encoding='utf8') as fp:
        networkx.drawing.nx_pydot.write_dot(graph, fp)

    
    (dot_graph, ) = pydot.graph_from_dot_file(dot_file_path)

    # Ref: https://github.com/pydot/pydot/issues/169
    for i, node in enumerate(dot_graph.get_nodes()):
        node.set_shape('box')
    
    for i, edge in enumerate(dot_graph.get_edges()):
        edge.set_label(edge.get('key'))

    png_file_name = apk_name + name + ".png"
    png_file_path = os.path.join(graph_dir, png_file_name)
    dot_graph.write_png(png_file_path)