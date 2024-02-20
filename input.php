<?php

ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

require_once './parse.php';

function main() {
    $SOURCES__REPLACE_REFERENCES_WITH_OBJECTS = true;
    $SOURCES__REPLACE_GROUPS_WITH_MULTIPLE_OBJECTS = true;
    $SOURCES__FLATTEN = true;

    $SERVICES__REPLACE_REFERENCES_WITH_OBJECTS = true;
    $SERVICES__FLATTEN = true;

    $DESTINATIONS__REPLACE_REFERENCES_WITH_OBJECTS = true;
    $DESTINATIONS__REPLACE_GROUPS_WITH_MULTIPLE_OBJECTS = true;
    $DESTINATIONS__FLATTEN = true;

    $DEBUG__SHOW_ALL_PARSED_OBJECTS = false;
    $DEBUG__PRINT_NULL_OBJECT_REFERENCES_AND_DIE = false;
    $DEBUG__ONLY_SHOW_WHERE_NOT_FLATTENED = false;

    $format = 'json';
    $asDownload = false;

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (isset($_REQUEST['DEBUG__SHOW_ALL_PARSED_OBJECTS'])) {
            $DEBUG__SHOW_ALL_PARSED_OBJECTS = true;
        }

        if (isset($_REQUEST['DEBUG__PRINT_NULL_OBJECT_REFERENCES_AND_DIE'])) {
            $DEBUG__PRINT_NULL_OBJECT_REFERENCES_AND_DIE = true;
        }

        if (isset($_REQUEST['DEBUG__ONLY_SHOW_WHERE_NOT_FLATTENED'])) {
            $DEBUG__ONLY_SHOW_WHERE_NOT_FLATTENED = true;
        }

        if (isset($_REQUEST['as_download'])) {
            $asDownload = true;
        }

        $format = $_REQUEST['format'];

        $webadminXML = file_get_contents($_FILES['fileWebadminXML']['tmp_name']);
        $confdXML = file_get_contents($_FILES['fileConfdXML']['tmp_name']);
    } else {
        $webadminXML = file_get_contents('./webadmin.xml');
        $confdXML = file_get_contents('./confd.xml');
    }

    //$jsonOriginal = parseXML($webadminXML, $confdXML);
    $json = parseXML($webadminXML, $confdXML);

    foreach ($json->firewall__rule_objects as $ruleKey => &$rule) {
        /** -------------------------------------------------------------------
         ** STRING REFERENCES -> OBJECTS (SOURCE)
         ** -------------------------------------------------------------------
         */

        if ($SOURCES__REPLACE_REFERENCES_WITH_OBJECTS) {
            foreach ($rule->sources as $key => &$ref) {
                $name = $ref;
                $ref = findInJSON($json, $ref);

                if ($ref === null && $DEBUG__PRINT_NULL_OBJECT_REFERENCES_AND_DIE) {
                    echo $name . PHP_EOL;
                }
            }
        }


        /** -------------------------------------------------------------------
         ** STRING REFERENCES -> OBJECTS (SERVICES)
         ** -------------------------------------------------------------------
         */

        if ($SERVICES__REPLACE_REFERENCES_WITH_OBJECTS) {
            foreach ($rule->services as $key => &$ref) {
                $name = $ref;
                $ref = findInJSON($json, $ref);

                if ($ref === null && $DEBUG__PRINT_NULL_OBJECT_REFERENCES_AND_DIE) {
                    echo $name . PHP_EOL;
                }
            }
        }


        /** -------------------------------------------------------------------
         ** STRING REFERENCES -> OBJECTS (DESTINATIONS)
         ** -------------------------------------------------------------------
         */

        if ($DESTINATIONS__REPLACE_REFERENCES_WITH_OBJECTS) {
            foreach ($rule->destinations as $key => &$ref) {
                $name = $ref;
                $ref = findInJSON($json, $ref);

                if ($ref === null && $DEBUG__PRINT_NULL_OBJECT_REFERENCES_AND_DIE) {
                    echo $name . PHP_EOL;
                }
            }
        }

        if ($DEBUG__PRINT_NULL_OBJECT_REFERENCES_AND_DIE) {
            continue;
        }
        

        /** -------------------------------------------------------------------
         ** GROUPS -> MULTIPLE SOURCE OBJECTS (SOURCE)
         ** -------------------------------------------------------------------
         */
        if ($SOURCES__REPLACE_GROUPS_WITH_MULTIPLE_OBJECTS) {
            $objects = array();
            foreach ($rule->sources as $key => &$ref) {
                if ($ref === null) {
                    $objects[] = null;
                    continue;
                }

                if (isset($ref->members)) {
                    foreach ($ref->members as &$member) {
                        $objects[] = findInJSON($json, $member);
                    }

                    unset($rule->sources[$key]);
                    continue;
                }
            }
            $rule->sources = array_merge($rule->sources, $objects);
        }


        /** -------------------------------------------------------------------
         ** GROUPS -> MULTIPLE SOURCE OBJECTS (DESTINATIONS)
         ** -------------------------------------------------------------------
         */

        if ($DESTINATIONS__REPLACE_GROUPS_WITH_MULTIPLE_OBJECTS) {
            $objects = array();
            foreach ($rule->destinations as $key => &$ref) {
                if ($ref === null) {
                    $objects[] = null;
                    continue;
                }

                if (isset($ref->members)) {
                    foreach ($ref->members as &$member) {
                        $objects[] = findInJSON($json, $member);
                    }

                    unset($rule->destinations[$key]);
                    continue;
                }
            }
            $rule->destinations = array_merge($rule->destinations, $objects);
        }


        /** -------------------------------------------------------------------
         ** FLATTEN SOURCES
         ** -------------------------------------------------------------------
         */

        if ($SOURCES__FLATTEN) {
            $expandedSources = array();
            foreach ($rule->sources as &$ref) {
                
                if ($ref === null) {
                    continue;
                }

                if (isset($ref->type) && $ref->type === 'host_object') {
                    ($ref->address !== '') ? $expandedSources[] = $ref->address : null;
                    $expandedSources = array_merge($expandedSources, $ref->hostnames);
                    continue;
                }

                if (isset($ref->type) && $ref->type === 'dns_host_object') {
                    $expandedSources[] = $ref->hostname;
                    continue;
                }

                if (isset($ref->type) && $ref->type === 'network_object') {
                    $expandedSources[] = $ref->address . '/' . $ref->netmask;
                    continue;
                }

                if (isset($ref->type) && $ref->type === 'network_range') {
                    $expandedSources[] = $ref->from . ' -> ' . $ref->to;
                    continue;
                }

                if (isset($ref->type) && $ref->type === 'ip_list') {
                    $expandedSources = array_merge($expandedSources, $ref->addresses);
                    continue;
                }
            }

            $rule->sources = $expandedSources;
        }


        /** -------------------------------------------------------------------
         ** FLATTEN SERVICES
         ** -------------------------------------------------------------------
         */

        if ($SERVICES__FLATTEN) {
            $newServices = array();
            foreach ($rule->services as &$ref) {
                isset($ref->name) ? $newServices[] = $ref->name : $newServices[] = null;
            }
            $rule->services = $newServices;
        }


        /** -------------------------------------------------------------------
         ** FLATTEN DESTINATIONS
         ** -------------------------------------------------------------------
         */
        
        if ($DESTINATIONS__FLATTEN) {
            $expandedDestinations = array();
            foreach ($rule->destinations as &$ref) {

                if (isset($ref->type) && $ref->type === 'host_object') {
                    ($ref->address !== '') ? $expandedDestinations[] = $ref->address : null;
                    $expandedDestinations = array_merge($expandedDestinations, $ref->hostnames);
                    continue;
                }

                if (isset($ref->type) && $ref->type === 'dns_host_object') {
                    $expandedDestinations[] = $ref->hostname;
                    continue;
                }

                if (isset($ref->type) && $ref->type === 'network_object') {
                    $expandedDestinations[] = $ref->address . '/' . $ref->netmask;
                    continue;
                }

                if (isset($ref->type) && $ref->type === 'network_range') {
                    $expandedDestinations[] = $ref->from . ' -> ' . $ref->to;
                    continue;
                }

                if (isset($ref->type) && $ref->type === 'ip_list') {
                    $expandedDestinations = array_merge($expandedDestinations, $ref->addresses);
                    continue;
                }
            }
            
            $rule->destinations = $expandedDestinations;
        }


        /** -------------------------------------------------------------------
         ** REMOVE UNWANTED RULES
         ** -------------------------------------------------------------------
         */

        if ($rule->action === 'drop') {
            unset($json->firewall__rule_objects[$ruleKey]);
            continue;
        }

        if ($rule->status === '0') {
            unset($json->firewall__rule_objects[$ruleKey]);
            continue;
        }

        /** -------------------------------------------------------------------
         ** REMOVE UNWANTED ATTRIBUTES
         ** -------------------------------------------------------------------
         */

        unset($rule->status);
        unset($rule->group);
        unset($rule->time);
        unset($rule->log);
        unset($rule->source_mac_addresses);
        unset($rule->action);
        unset($rule->comment);
    }

    /** -------------------------------------------------------------------
     ** DEBUGGING
     ** -------------------------------------------------------------------
     */

    if ($DEBUG__PRINT_NULL_OBJECT_REFERENCES_AND_DIE) {
        die();
    }

    if (!$DEBUG__SHOW_ALL_PARSED_OBJECTS) {
        $j = new \stdClass();
        $j->firewall__rule_objects = $json->firewall__rule_objects;
        $json = $j;
    }

    if ($DEBUG__ONLY_SHOW_WHERE_NOT_FLATTENED) {
        foreach ($json->firewall__rule_objects as $ruleKey => &$rule) {
            foreach ($rule->sources as $key => $value) {
                if (is_string($value)) {
                    unset($rule->sources[$key]);
                }
            }
        
            foreach ($rule->services as $key => $value) {
                if (is_string($value)) {
                    unset($rule->services[$key]);
                }
            }

            foreach ($rule->destinations as $key => $value) {
                if (is_string($value)) {
                    unset($rule->destinations[$key]);
                }
            }

            if (count($rule->sources) === 0 && count($rule->services) === 0 && count($rule->destinations) === 0) {
                unset($json->firewall__rule_objects[$ruleKey]);
                continue;
            }

            if (count($rule->sources) === 0) {
                unset($json->firewall__rule_objects[$ruleKey]->sources);
            }

            if (count($rule->services) === 0) {
                unset($json->firewall__rule_objects[$ruleKey]->services);
            }

            if (count($rule->destinations) === 0) {
                unset($json->firewall__rule_objects[$ruleKey]->destinations);
            }
        }
    }

    /** -------------------------------------------------------------------
     ** OUTPUT OPTIONS
     ** -------------------------------------------------------------------
     */

    $filename = 'firewall_rules__' . substr(md5($webadminXML . $confdXML), 0, 5) . '__' . date('Ymd') . '_' . date('His') . '.' . $format;

    if ($asDownload) {
        header('Content-Disposition: attachment; filename="' . $filename  . '"');
    }

    if ($format === 'json') {
        header('Content-Type: application/json');
        echo json_encode($json);
    } else if ($format === 'csv') {
        if ($asDownload) {
            header('Content-Type: text/csv');
        } else {
            header('Content-Type: text/plain');
        }
        echo jsonToCSV($json);
    }
}

function findInJSON($json, $key) {
    foreach ($json as $jkey => $jvalue) {
        if ($jkey === $key) {
            return $jvalue;
        }

        if (isset($json->$jkey) && is_array($json->$jkey)) {
            $result = findInJSON($json->$jkey, $key);

            if ($result !== null) {
                return $result;
            }
        }
    }

    return null;
}

function jsonToCSV($json) {
    $csv = 'Rule;Sources;Services;Destinations' . PHP_EOL;
    foreach ($json->firewall__rule_objects as $key => $rule) {
        $maxArraySize = max([count($rule->sources), count($rule->services), count($rule->destinations)]);

        for ($i = 0; $i < $maxArraySize; $i++) {
            $ref = $i === 0 ? $key : ' ';
            $src = isset($rule->sources[$i]) ? $rule->sources[$i] : '';
            $srv = isset($rule->services[$i]) ? $rule->services[$i] : '';
            $dst = isset($rule->destinations[$i]) ? $rule->destinations[$i] : '';

            $csv .= implode(';', [$ref, $src, $srv, $dst]) . PHP_EOL;
        }
    }

    return $csv;
}

main();