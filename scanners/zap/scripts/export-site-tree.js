/**
 * Script to traverse the site tree and export node information to a JSON file
 *
 * This script retrieves the root of the site tree from the current ZAP session,
 * traverses each child node, and collects relevant information such as node name,
 * HTTP method, and status code. The collected data is then written to a JSON file
 * named 'zap_site_tree.json' in the session's results directory
 */

var File = Java.type('java.io.File');
var FileWriter = Java.type('java.io.FileWriter');
var BufferedWriter = Java.type('java.io.BufferedWriter');

function listChildren(node, resultList) {
    for (var j = 0; j < node.getChildCount(); j++) {
        listChildren(node.getChildAt(j), resultList);
    }

    if (node.getChildCount() == 0) {
        var href = node.getHistoryReference();
        var nodeInfo = {};
        nodeInfo["name"] = node.getHierarchicNodeName();

        if (href != null) {
            nodeInfo["method"] = href.getMethod();
            nodeInfo["status"] = href.getStatusCode();
        } else {
            nodeInfo["method"] = "No History Reference";
            nodeInfo["status"] = "No History Reference";
        }

        resultList.push(nodeInfo);
    }
}

try {
    var root = model.getSession().getSiteTree().getRoot();
    var resultList = [];

    listChildren(root, resultList);

    var jsonOutput = JSON.stringify(resultList, null, 4);

    var defaultResultsDir = model.getSession().getSessionFolder();
    var outputFilePath = new File(defaultResultsDir, "zap_site_tree.json").getAbsolutePath();

    var file = new File(outputFilePath);
    var writer = new BufferedWriter(new FileWriter(file));
    writer.write(jsonOutput);
    writer.close();

    print("Site tree data has been written to: " + outputFilePath);

} catch (e) {
    print("An error occurred: " + e);
}
