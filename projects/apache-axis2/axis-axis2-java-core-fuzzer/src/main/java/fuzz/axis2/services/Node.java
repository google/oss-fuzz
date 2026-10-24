// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package fuzz.axis2.services;

/** Self-referential type: the shape the 2.0.2 multiref/depth bounds were added for. */
public class Node {
    private String name;
    private Node next;
    private Node[] children;

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public Node getNext() { return next; }
    public void setNext(Node next) { this.next = next; }
    public Node[] getChildren() { return children; }
    public void setChildren(Node[] children) { this.children = children; }
}
