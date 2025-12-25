



testbed-cli.py

    testbed                 Testbed related operations

        query               Query defined testbed based on various filters
        status              Check if testbed is deployed on any server
        show                Show testbed definition
        add-topo            Deploy testbed topology
        remove-topo         Remove testbed topology
        gen-config          Generate configuration for testbed DUTs
        deploy-config       Generate and deploy configuration for testbed DUTs
        gen-inventory       Generate inventory file for testbed
        gen-ssh-config      Generate ssh configuration for testbed

    graph                   Connection graph related information

        check               Check graph issue, like duplicated vlan






Given a testbed, show it's fanout connections: testbed-cli.py testbed show --tb xx --connection


Given current testbed connections,

- find free fanout ports
- find free vlan ranges
- check duplicated vlan
- show its current connection
-
