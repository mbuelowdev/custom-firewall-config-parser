<?php

require_once './xml_utils.php';

function parseXML($webadminXML, $confdXML) {
    $docWebadminXML = new DOMDocument();
    $docWebadminXML->loadXML($webadminXML);

    $docConfdXML = new DOMDocument();
    $docConfdXML->loadXML($confdXML);

    $json = new \stdClass();
    $json->firewall__rule_objects = getAndMapXMLObjectToJSON($docWebadminXML, 'packetfilter', 'firewall rule', ['status', 'group', 'sources' => 'type_array', 'services' => 'type_array', 'destinations' => 'type_array', 'action', 'comment', 'time', 'log', 'source_mac_addresses']);
    $json->network__host_objects = getAndMapXMLObjectToJSON($docWebadminXML, 'host', 'host', ['name', 'interface', 'address', 'address6', 'hostnames' => 'type_array', 'reverse_dns', 'duids' => 'type_array', 'comment'], 'host_object');
    $json->network__dns_host_objects = getAndMapXMLObjectToJSON($docWebadminXML, 'dns_host', 'DNS host', ['name', 'interface', 'hostname', 'comment'], 'dns_host_object');
    $json->network__dns_group_objects = getAndMapXMLObjectToJSON($docWebadminXML, 'dns_group', 'DNS group', ['name', 'interface', 'hostname', 'comment']);
    $json->network__network_objects = getAndMapXMLObjectToJSON($docWebadminXML, 'network', 'network', ['name', 'interface', 'address', 'netmask', 'address6', 'netmask6', 'comment'], 'network_object');
    $json->network__network_group_objects = getAndMapXMLObjectToJSON($docWebadminXML, 'group', 'network group', ['name', 'members' => 'type_array', 'comment']);
    $json->network__availability_groups = getAndMapXMLObjectToJSON($docWebadminXML, 'availability_group', 'availability group', ['name', 'members' => 'type_array', 'timeout', 'sticky', 'comment']);
    $json->network__interface_addresses = getAndMapXMLObjectToJSON($docWebadminXML, 'interface_address', 'interface address', ['name', 'address', 'address6', 'comment']);
    $json->network__interface_networks = getAndMapXMLObjectToJSON($docWebadminXML, 'interface_network', 'interface network', ['name', 'address', 'netmask', 'address6', 'netmask6', 'comment'], 'network_object');
    $json->network__interface_broadcasts = getAndMapXMLObjectToJSON($docWebadminXML, 'interface_broadcast', 'interface broadcast address', ['name', 'address', 'comment']);
    $json->network__any = getAndMapXMLObjectToJSON($docWebadminXML, 'any', 'any address', ['name', 'interface', 'address', 'netmask', 'address6', 'netmask6', 'comment'], 'network_object');
    $json->network__user_or_group_network = getAndMapXMLObjectToJSON($docWebadminXML, 'aaa', 'user or group network', ['name', 'addresses' => 'type_array', 'addresses6' => 'type_array', 'comment'], 'ip_list');
    $json->network__network_ranges = getAndMapXMLObjectToJSON($docConfdXML, 'range', 'INTERNAL', ['name', 'resolved', 'resolved6', 'from', 'to', 'from6', 'to6', 'comment', 'comment'], 'network_range');

    $json->services__tcp = getAndMapXMLObjectToJSON($docWebadminXML, 'tcp', 'TCP service', ['name', 'src_low', 'src_high', 'dst_low', 'dst_high', 'comment']);
    $json->services__udp = getAndMapXMLObjectToJSON($docWebadminXML, 'udp', 'UDP service', ['name', 'src_low', 'src_high', 'dst_low', 'dst_high', 'comment']);
    $json->services__tcpudp = getAndMapXMLObjectToJSON($docWebadminXML, 'tcpudp', 'TCP and UDP service', ['name', 'src_low', 'src_high', 'dst_low', 'dst_high', 'comment']);
    $json->services__icmp = getAndMapXMLObjectToJSON($docWebadminXML, 'icmp', 'ICMPv4 service', ['name', 'type', 'code', 'comment']);
    $json->services__icmpv6 = getAndMapXMLObjectToJSON($docWebadminXML, 'icmpv6', 'ICMPv6 service', ['name', 'type', 'code', 'comment']);
    $json->services__ip = getAndMapXMLObjectToJSON($docWebadminXML, 'ip', 'IP service', ['name', 'proto', 'comment']);
    $json->services__groups = getAndMapXMLObjectToJSON($docWebadminXML, 'group', 'service group', ['name', 'members' => 'type_array', 'comment']);
    $json->services__any = getAndMapXMLObjectToJSON($docWebadminXML, 'any', 'any service', ['name', 'comment']);

    return $json;
}

function getAndMapXMLObjectToJSON($document, $rootTagName, $rootTagDescription, $arrFields, $objectType = null) {
    $result = array();

    $xml = findNodeByTagNameAndDescription($document, $rootTagName, $rootTagDescription, ['type' => '1']);

    // Ignore non-existing nodes
    if ($xml === null) {
        return array();
    }

    $xml = getFirstNodeByName($xml, 'content');

    foreach ($xml->childNodes as $xmli) {
        if (get_class($xmli) != 'DOMElement') continue;

        $name = $xmli->tagName;

        $xmli = getFirstNodeByName($xmli, 'content');

        $obj = new \stdClass();

        if ($objectType !== null) {
            $obj->type = $objectType;
        }

        foreach ($arrFields as $key => $value) {
            if ($value === 'type_literal') {
                $nodeField = getFirstNodeByName($xmli, $key);
                $obj->$key = getFirstNodeByName($nodeField, 'content')->nodeValue;
                continue;
            }

            if ($value === 'type_array') {
                $nodeField = getFirstNodeByName($xmli, $key);
                $obj->$key = array();
                foreach (getAllNodesByName($nodeField, 'content') as $e) {
                    $obj->$key[] = $e->nodeValue;
                }
                continue;
            }

            $nodeField = getFirstNodeByName($xmli, $value);
            $obj->$value = getFirstNodeByName($nodeField, 'content')->nodeValue;
        }


        $result[$name] = $obj;
    }

    return $result;
}