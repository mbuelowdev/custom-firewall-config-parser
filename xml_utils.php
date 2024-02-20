<?php

function getFirstNodeByName($node, $name) {
    foreach ($node->childNodes as $child) {
        if (isset($child->tagName) && $child->tagName === $name) {
            return $child;
        }
    }

    return null;
}

function getAllNodesByName($node, $name) {
    $nodes = array();

    foreach ($node->childNodes as $child) {
        if (isset($child->tagName) && $child->tagName === $name) {
            $nodes[] = $child;
        }
    }

    return $nodes;
}

function findNodeByTagNameAndDescription($doc, $tagName, $description, $arrAttributes = array()) {
    $nodes = $doc->getElementsByTagName($tagName);

    foreach($nodes as $node) {
        if (count($arrAttributes) > 0) {
            $matchingAttributes = 0;
            foreach ($node->attributes as $attribute) {
                if (isset($arrAttributes[$attribute->name])) {
                    if ($arrAttributes[$attribute->name] === $attribute->value) {
                        $matchingAttributes++;
                    }
                }
            }

            if (count($arrAttributes) !== $matchingAttributes) {
                continue;
            }
        }

        $dt = getFirstNodeByName($node, 'descr');

        if ($dt === null) {
            continue;
        }

        if ($dt->nodeValue === $description) {
            return $node;
        }
    }

    return null;
}