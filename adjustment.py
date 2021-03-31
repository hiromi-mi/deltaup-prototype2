class Label2:
    pass

class Node:
    def __init__(self):
        pass

class Problem:
    def __init__(self):
        self.queue = []
        self.orig_root = Node()
        self.new_node = Node()
        self.queue.append(self.new_node)
        self.orig_trace = []

        while (len(self.queue) > 0):
            node = self.queue[-1]
            self.try_solve(node)

    def try_solve(self, new_node):
        front = new_node.edges[-1]
        if front.in_edge.assignment:
            # delete front
            new_node.edges.pop()

        orig_node = self.find_corresponding_orig_node(new_node)
        if not orig_node:
            print("Cannot find model node")
            return

        self.extend_nodes(orig_node, self.orig_trace)
        # skip_committted_labels()
        if len(orig_node.edges) == 0:
            print("Cannot find model node due to no edges")
            return

        orig_match = orig_node.edges[-1]
        new_match = new_node.edges[-1]
        if orig_match.count > 1.1 * new_match.count or new_match.count > 1.1 * orig_match.count:
            print("Distribution Mismatch")
            return

        orig_node.edges.pop()
        new_node.edges.pop()

        new_label_info = new_match.in_edge
        orig_label_info = orig_match.in_edge
        m_index = new_label_info.label.index
        if m_index != "noindex":
            print("Error: Cannot Unassigned Model Label")
            return

        self.assign_and_extend(new_label_info, orig_label_info)

        # find matches within new match
        self.add_to_queue(new_match)
        self.add_to_queue(new_node)

    def add_to_queue(self, new_node):
        self.queue.append(new_node)

    def assign_and_extend(self, new_label_info, orig_label_info):
        self.assignone(new_label_info, orig_label_info)
        self.extend_assignment(new_label_info, orig_label_info)

    def assignone(self, new_label_info, orig_label_info):
        new_label_info.label.index = orig_label_info.label.index

        new_label_info.assignment = orig_label_info
        orig_label_info.assignment = new_label_info

    def find_corresponding_orig_node(self, node):
        if not node.prev:
            return self.orig_root
        new_parent = node.prev
        orig_parent = self.find_corresponding_orig_node(new_parent)
        if not orig_parent:
            return orig_parent

        self.extend_nodes(orig_parent, self.orig_trace)

        new_label_info = node.in_edge
        orig_label_info = new_label_info.assignment

        return orig_parent.edges[orig_parent.edges.index(orig_label_info)]


    def extend_assignment(self, new_label_info, orig_label_info):
        pass

    def extend_nodes(self, node, trace):
        if len(node.edges) > 0 or len(node.places) == 0:
            return

        for i in range(node.places):
            index = node.places[i]
            if index < len(trace):
                label_info = trace[index]
                slot = node.edges[node.edges.index(label_info)]
                pass

