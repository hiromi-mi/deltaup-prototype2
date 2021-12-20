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
    rva: int

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
        self.extend_nodes(node, self.new_trace)
        
        while node.edges_in_frequency_order[0].in_edge.assignment:
            if len(node.edges_in_frequency_order) == 0:
                break
            node.edges_in_frequency_order.pop()


    def try_solve(self, new_node : Node):
        front = new_node.edges_in_frequency_order[-1]
        if front.in_edge.assignment:
            # delete front
            new_node.edges.pop()
            self.add_to_queue(front)
            self.add_to_queue(new_node)
            return

        orig_node = self.find_corresponding_orig_node(new_node)
        if not orig_node:
            print("Cannot find model node")
            return

        self.extend_nodes(orig_node, self.orig_trace)
        self.skip_committed_labels(orig_node)
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

    def _extend_assignment_forward(self, new_info_next: LabelInfo, old_info_next: LabelInfo, new_rva_base: int, old_rva_base: int):
        while (new_info_next and old_info_next):
            if old_info_next.assignment:
                break

            # 最初の old_rva_base と new_info_next を (2,3,...) 続けている
            old_rva = old_info_next.next_addr_labelinfo.rva
            new_rva = new_info_next.next_addr_labelinfo.rva

            if old_rva - old_rva_base != new_rva - new_rva_base:
                pass

            old_info_next_next = old_info_next.next_addr_labelinfo
            new_info_next_next = new_info_next.next_addr_labelinfo

            self.assignone(new_info_next, old_info_next)

            if (new_info_next.refs_cnt == old_info_next.refs_cnt and new_info_next.refs_cnt == 1):
                self.extend_sequence(new_info_next.positions_[0], old_info_next.positions_[0])
                self.extend_sequence_backwards(new_info_next.positions_[0], old_info_next.positions_[0])

            new_info_next = new_info_next_next
            old_info_next = old_info_next_next

    def _extend_assignment_backward(self, new_info_prev: LabelInfo, old_info_prev: LabelInfo, new_rva_base: int, old_rva_base: int):
        while (new_info_prev and old_info_prev):
            if old_info_prev.assignment:
                break

            # 最初の old_rva_base と new_info_next を (2,3,...) 続けている
            old_rva = old_info_prev.prev_addr_labelinfo.rva
            new_rva = new_info_prev.prev_addr_labelinfo.rva

            if old_rva - old_rva_base != new_rva - new_rva_base:
                pass

            old_info_prev_prev = old_info_prev.prev_addr_labelinfo
            new_info_prev_prev = new_info_prev.prev_addr_labelinfo

            self.assignone(new_info_prev, old_info_prev)

            if (new_info_prev.refs_cnt == old_info_prev.refs_cnt):
                self.extend_sequence(new_info_prev.positions_[0], old_info_prev.positions_[0])
                self.extend_sequence_backwards(new_info_prev.positions_[0], old_info_prev.positions_[0])

            new_info_prev = new_info_prev_prev
            old_info_prev = old_info_prev_prev
    def extend_assignment(self, new_info : LabelInfo, old_info : LabelInfo):
        # 前後のAddressを比較して, その old_rva と new_rva が一致しているかどうかを判定
        old_rva_base = old_info.label.rva
        new_rva_base = new_info.label.rva

        new_info_next = new_info.next_addr_labelinfo
        old_info_next = old_info.next_addr_labelinfo

        # 前方探索
        self._extend_assignment_forward(new_info_next, old_info_next, new_rva_base, old_rva_base)

        # 後方探索
        new_info_prev = new_info.prev_addr_labelinfo
        old_info_prev = old_info.prev_addr_labelinfo

        self._extend_assignment_backward(new_info_prev, old_info_prev, new_rva_base, old_rva_base)

    def extend_sequence(self, p_pos_start : int, m_pos_start : int):
        p_pos = p_pos_start + 1
        m_pos = m_pos_start + 1

        while (p_pos < len(self.new_trace) and m_pos < len(self.orig_trace)):
            p_info = self.new_trace[p_pos]
            m_info = self.orig_trace[m_pos]

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
            p_info = self.new_trace[p_pos]
            m_info = self.orig_trace[m_pos]
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

