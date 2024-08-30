/* File: QueryAllFunctions.java
 * Author: Landen Doty
 * Description: Use Ghidra's BSim API to query a BSim H2 database for function matches in a binary
 * Credit: Based off of the Ghidra Developer's example script
 */

import java.net.URL;
import java.util.Iterator;

import java.io.IOException;
import java.io.File;
import java.io.FileWriter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;

import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.protocol.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class QueryAllFunctions extends GhidraScript {

	private static final int MATCHES_PER_FUNC = 1;
	private static final double SIMILARITY_BOUND = 0.0;
	private static final double CONFIDENCE_BOUND = 0.9;

	private FunctionDatabase DATABASE = null;
	private static final String out_path = "./function_similarities.txt";
	
	@Override
	public void run() throws Exception {
	/* main entrypoint to script. open database and iter over all symbols to query
 	*  args: path to bsim directory
 	*  note: GhidraScript.run() doesn't explicitly take args. Get using
 	* 	getScriptArgs()	
 	*/

        	// process arguments
		if (currentProgram == null) {
			println("No current program");
			return;
		}
			
		String args[] = getScriptArgs();
       		String fn_name_filter = ""; 
        	if(args.length < 1) {
            		println("Provide a database url!");
            		return;
        	}
        
		if(args.length >= 2){
            		fn_name_filter = args[1];
        	}
        
        	// Open the BSim database provided by args
        	String database_url = args[0];
		URL url = BSimClientFactory.deriveBSimURL(database_url);
		try {			
			DATABASE = BSimClientFactory.buildClient(url, false);
            		if(! DATABASE.initialize()) {
				println(DATABASE.getLastError().message);
              			return;
			} 
		} catch(Exception e) {
			println("Failed to open database");
            		return;
		} 

        	// Initialize output file
		String[] split = database_url.split("/", 0);
		String db_path_base = split[split.length-1]; 	
		File out_file = init_results_file(db_path_base);
		FileWriter fw = new FileWriter(out_file, true); // get path back from init, true = append

        	// Iterate over functions
        	// Query
        	// Write results
        	int num_functions = 0;
		for(FunctionIterator i = currentProgram.getFunctionManager().getFunctions(true); i.hasNext(); ) {
			Function f = i.next();
			if(f != null) {
            			String result = run_query(f, fn_name_filter);
				if(!result.isEmpty()) {
					fw.write(result);
					num_functions++;
				}
			}
		}
        	fw.write(String.valueOf(num_functions) + "\n");
		fw.close();	
	}

	private File init_results_file(String database) throws Exception {
    	/*
     	* Initialize output file of form:
     	* database_name, binary_path, similarity bound, confidence bound
     	*/
		File out_file = null;
		try {
			StringBuffer buf = new StringBuffer(); 
			buf.append(currentProgram.getExecutablePath() + ",");
			buf.append(database + ",");
			buf.append(String.valueOf(SIMILARITY_BOUND) + ",");
			buf.append(String.valueOf(CONFIDENCE_BOUND) + "\n");
			out_file = new File(out_path);
			FileWriter fw = new FileWriter(out_file, false); // don't append, starting new file
			fw.write(buf.toString());
			fw.close();
		}
		catch(IOException e) { 
			println("Failed to init results file");
		}
		
		return out_file;
	}

	private String run_query(Function func, String filter) throws Exception {
	/* Perform query over a single function and generate a result string of
     	* form:
     	*
 	*/ 
		GenSignatures gensig = new GenSignatures(false);
		StringBuffer buf = new StringBuffer();
		try {
            		// generate a signature/feature vector for the target function
			gensig.setVectorFactory(DATABASE.getLSHVectorFactory());
			gensig.openProgram(currentProgram, null, null, null, null, null);
			DescriptionManager manager = gensig.getDescriptionManager();
			gensig.scanFunction(func);
            
            		// configure a query for the function
			QueryNearest query = new QueryNearest();
			query.manage = manager;
			query.max = MATCHES_PER_FUNC;
			query.thresh = SIMILARITY_BOUND;
			query.signifthresh = CONFIDENCE_BOUND;

            		// perform the query
			ResponseNearest response = query.execute(DATABASE);
			if (response == null) {
                		println(DATABASE.getLastError().message);
			}
		
            		// process result
			Iterator<SimilarityResult> iter = response.result.iterator();
			while (iter.hasNext()) { // while there exists a match
				SimilarityResult result = iter.next();
				FunctionDescription base = result.getBase();
				String source_fn = base.getFunctionName();				
		
				Iterator<SimilarityNote> subiter = result.iterator();
				while (subiter.hasNext()) {
					SimilarityNote note = subiter.next();
					FunctionDescription fdesc = note.getFunctionDescription();
                  
                    			String matched_fn = fdesc.getFunctionName();

                    			// currently filtering for 
                    			// match startswtih filter && source_fn startswith filter
                    			if(filter != "" && !source_fn.startsWith(filter) && !matched_fn.startsWith(filter)) {
                        			continue;
                    			}

					buf.append(source_fn + ","); // source fn in binary
					buf.append(matched_fn + ","); // matched fn in database
					buf.append(note.getSimilarity() + ","); // similarity
					buf.append(note.getSignificance() + "\n"); // signifiance
				}
			}
		}
		catch(Exception e) {
			println(e.getMessage());
		}
		finally {
			gensig.dispose();
		}
		return buf.toString();
	} 
}
