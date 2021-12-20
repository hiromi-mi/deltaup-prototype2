from typing import ClassVar, Dict, List

from disassembler import Receptor

class Label:
    def __init__(self):
        pass
    pass

class AdjustmentAll:
    def __init__(self):
        # {Label*, LabelInfo}
        self.label_infos = {}
        self.old_abs32 = []
        self.new_rel32 = []

    # make_label_info + reference_label
    #def make_label_infos(self, label, position):
    def reference_label(self, trace, is_old, label : Label):
        slot = self.label_infos[label]
        if not slot.label:
            slot.label = label
            #slot.is_old = is_old

        slot.positions_.append(label.position)
        return slot

class LabelInfo:
    assignment: 'LabelInfo'
    label: Label
    is_model : bool
    refs_cnt : int
    next_addr_labelinfo : 'LabelInfo'
    prev_addr_labelinfo : 'LabelInfo'

    positions_ : List[int]
    def __init__(self):
        self.positions_ = []

class Node:
    in_edge: LabelInfo
    prev: 'Node'
    count : int
    length : int
    edges: Dict[LabelInfo, 'Node']
    places: List[int]
    edges_in_frequency_order : List['Node']

    def __init__(self, in_edge : LabelInfo, prev: 'Node'):
        self.in_edge = in_edge
        self.prev = prev
        # TODO prev.length == 0
        self.length = prev.length + 1
        self.edges_in_frequency_order = []
        pass

    def Weight() -> int:
        return 

Trace = List[LabelInfo]

class Problem:
    worklist: List[Node]
    orig_root: Node
    new_node: Node
    orig_trace : Trace
    new_trace: Trace

    # in_queue : bool # unused
    def __init__(self, receptor_old : Receptor, receptor_new : Receptor):
        self.worklist = []
        self.orig_root = Node()
        self.new_node = Node()
        self.worklist.append(self.new_node)
        self.orig_trace = []
        self.receptor_old = receptor_old
        self.receptor_new = receptor_new

        while (len(self.worklist) > 0):
            node = self.worklist.pop()
            self.try_solve(node)

    def skip_committed_labels(self, node: Node):
        self.extend_nodes(node, self.orig_trace)
        
        while node.edges_in_frequency_order[0].in_edge.assignment:
            if len(node.edges_in_frequency_order) == 0:
                break
            node.edges_in_frequency_order.pop()
            

    def try_solve(self, new_node : Node):
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

    def add_to_queue(self, new_node: Node):
        self.extend_nodes(new_node, self.orig_trace)
        self.worklist.append(new_node)

    def assign_and_extend(self, new_label_info : LabelInfo, orig_label_info : LabelInfo):
        self.assignone(new_label_info, orig_label_info)
        self.extend_assignment(new_label_info, orig_label_info)

    def assignone(self, new_label_info : LabelInfo, orig_label_info : LabelInfo):
        new_label_info.label.index = orig_label_info.label.index

        new_label_info.assignment = orig_label_info
        orig_label_info.assignment = new_label_info

    def find_corresponding_orig_node(self, node : Node) -> Node:
        if not node.prev:
            return self.orig_root
        new_parent = node.prev
        orig_parent = self.find_corresponding_orig_node(new_parent)
        if not orig_parent:
            return None

        self.extend_nodes(orig_parent, self.orig_trace)

        new_label_info = node.in_edge
        orig_label_info = new_label_info.assignment

        return orig_parent.edges[orig_parent.edges.index(orig_label_info)]


    def extend_assignment(self, new_info : LabelInfo, old_info : LabelInfo):
        # 前後のAddressを比較して, その old_rva と new_rva が一致しているかどうかを判定
        old_rva_base = old_info.label.rva
        new_rva_base = new_info.label.rva

        new_info_next = new_info.next_addr
        old_info_next = old_info.next_addr

        while (new_info_next and old_info_next):
            if old_info_next.assignment:
                break

            # 最初の old_rva_base と new_info_next を (2,3,...) 続けている
            old_rva = old_info_next.next_addr
            new_rva = new_info_next.next_addr

            if old_rva - old_rva_base != new_rva - new_rva_base:
                pass

    def extend_sequence(self, p_pos_start : int, m_pos_start : int):
        p_pos = p_pos_start + 1
        m_pos = m_pos_start + 1

        while (p_pos < len(self.p_trace) and m_pos < len(self.m_trace)):
            p_info = self.p_trace[p_pos]
            m_info = self.m_trace[m_pos]

            if (p_info.assignment and m_info.assignment):
                if p_info.label.index == m_info.label.index:
                    break
                p_pos += 1
                m_pos += 1
                continue
            if p_info.refs != m_info.refs:
                break
            self.assignone(p_info, m_info)
            p_pos += 1
            m_pos += 1
        return p_pos - p_pos_start

    def extend_sequence_backwards(self, p_pos_start :int, m_pos_start:int) -> int:
        if p_pos_start == 0 or m_pos_start == 0:
            return 0

        p_pos = p_pos_start - 1
        m_pos = m_pos_start - 1

        while (p_pos > 0 and m_pos > 0):
            p_info = self.p_trace[p_pos]
            m_info = self.m_trace[m_pos]
            if (p_info.assignment and m_info.assignment):
                if p_info.label.index == m_info.label.index:
                    break
                p_pos -= 1
                m_pos -= 1
                continue
            if p_info.refs != m_info.refs:
                break
            self.assignone(p_info, m_info)
            p_pos -= 1
            m_pos -= 1
        return p_pos - p_pos_start

    def extend_nodes(self, node : Node, trace):
        if len(node.edges) > 0 or len(node.places) == 0:
            return

        for i in range(node.places):
            index = node.places[i]
            if index < len(trace):
                label_info = trace[index]
                slot = node.edges[node.edges.index(label_info)]
                pass

