/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Example of querying a BSim database about a single function
//@category BSim

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

	private static final int MATCHES_PER_FUNC = 5;
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
        String database_url = args[0];

		URL url = BSimClientFactory.deriveBSimURL(database_url);
		try {			
			DATABASE = BSimClientFactory.buildClient(url, false);
			if(! DATABASE.initialize()) {
				println(DATABASE.getLastError().message);
			} 
		} catch(Exception e) {
			println("Failed to open database");
		} 

		String[] split = database_url.split("/", 0);
		String db_path_base = split[split.length-1]; 
	
		File out_file = init_results_file(db_path_base);
		FileWriter fw = new FileWriter(out_file, true); // get path back from init, true = append

        int num_functions = 0;
		for(FunctionIterator i = currentProgram.getFunctionManager().getFunctions(true); i.hasNext(); ) {
			Function f = i.next();
			if(f == null) { continue; }
            num_functions++;
            String result = run_query(f, fn_name_filter);
			fw.write(result);
		}
        fw.write(String.valueOf(num_functions) + "\n");
		fw.close();	
	}

	private File init_results_file(String database) throws Exception {
		File out_file = null;
		try {
			StringBuffer buf = new StringBuffer(); 
			buf.append(database + ",");
			buf.append(currentProgram.getExecutablePath() + ",");
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
	/* run query over a single function
 	 * TODO: currently print results but need to output to json
 	 */ 
		GenSignatures gensig = new GenSignatures(false);
		StringBuffer buf = new StringBuffer();
		try {
			gensig.setVectorFactory(DATABASE.getLSHVectorFactory());
			gensig.openProgram(currentProgram, null, null, null, null, null);

			DescriptionManager manager = gensig.getDescriptionManager();
			gensig.scanFunction(func);

			QueryNearest query = new QueryNearest();
			query.manage = manager;
			query.max = MATCHES_PER_FUNC;
			query.thresh = SIMILARITY_BOUND;
			query.signifthresh = CONFIDENCE_BOUND;

			ResponseNearest response = query.execute(DATABASE);
			if (response == null) {
				return "";
			}
			
			// modify this to output to json, txt, something to do analysis over
			Iterator<SimilarityResult> iter = response.result.iterator();
			while (iter.hasNext()) {
				SimilarityResult sim = iter.next();
				FunctionDescription base = sim.getBase();
				String db_fn = base.getFunctionName();				
		
				Iterator<SimilarityNote> subiter = sim.iterator();
				while (subiter.hasNext()) {
					SimilarityNote note = subiter.next();
					FunctionDescription fdesc = note.getFunctionDescription();
					ExecutableRecord exerec = fdesc.getExecutableRecord();
                    
                    if(filter != "" && ! fdesc.getFunctionName().startsWith(filter)) {
                        continue;
                    }

					buf.append(db_fn + ","); // function in db
					buf.append(fdesc.getFunctionName() + ","); // function in binary
					buf.append(note.getSimilarity() + ","); // similarity
					buf.append(note.getSignificance() + "\n"); // signifiance
				}
			}
		}
		finally {
			gensig.dispose();
		}
		return buf.toString();
	} 

}
