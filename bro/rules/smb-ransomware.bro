## Source: https://github.com/fox-it/bro-scripts/blob/master/smb-ransomware/smb-ransomware.bro
@load base/frameworks/files
@load base/protocols/smb
@load base/frameworks/notice
@load base/frameworks/sumstats

global fuidmap : set[string];

module FoxCryptoRansom;

export {
	redef enum Notice::Type += {
		## Notice corresponding to a possible ransomware attack
		RANSOMWARE_SMB
	};

	## Entropy check on the first packet send
	const enc_off = 0 &redef;

	## Entropy check on certain bytes
	const enc_sdata = 0 &redef;
	const enc_edata = 1000 &redef;

	## Entropy and Mean corresponding to a possible ransomware attack
	const enc_entropy = 7.5 &redef;
	const enc_mean = 125 &redef;

	## Notice values corresponding to a possible ransomware attack
	const threshold_time = 30sec &redef;
	const threshold_limit = 5.0 &redef;

	## Ignore list for certain filenames
	const ignore_list = /GoogleChrome/ &redef;

	redef enum Log::ID += {LOG};
		type Info: record {
			ts: time &log;
			filename: string &log;
			entropy: double &log;
			mean: double &log;
	};
}

event chunk_event (f: fa_file, data: string, off: count)
{
	if ( off == enc_off ) {
		local fox_entropy =  find_entropy(data[enc_sdata:enc_edata]);
		if ( fox_entropy$entropy >= enc_entropy && fox_entropy$mean >= enc_mean ) {

			SumStats::observe("SMB traffic detected", SumStats::Key(), SumStats::Observation($num=1));

			local rec: FoxCryptoRansom::Info = [ $ts=network_time(), $filename = f$info$filename, $entropy=fox_entropy$entropy, $mean=fox_entropy$mean ];
			Log::write(FoxCryptoRansom::LOG, rec);
		}
	}
}


event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
{
	if (f$source == "SMB"){

		local filename = "UNKNOWN";

		if (f$info?$filename){
			filename = f$info$filename;
		}

		local mime_type = "UNKNOWN";

		if (f$info?$mime_type){
			mime_type = f$info$mime_type;
		}

		if (mime_type == "UNKNOWN"){

			if (ignore_list in filename){
				return;
			}else{

				if ( ! c$smb_state$current_file?$action){
					return ;
				}else{

					if (c$smb_state$current_file$action == SMB::FILE_WRITE){
						local fuid = c$smb_state$current_file$fuid;

						if (fuid !in fuidmap){
							Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, Files::AnalyzerArgs($chunk_event=chunk_event));
							add fuidmap[fuid];
						}
					}else{
					}
				}
			}
		}
	}
}

event bro_init()
{
	local r1 = SumStats::Reducer($stream="SMB traffic detected",
								$apply=set(SumStats::SUM));

	SumStats::create([$name = "Ransomware detection",
					$epoch = threshold_time,
					$reducers = set(r1),
					$threshold = threshold_limit,
					$threshold_val(key: SumStats::Key, result: SumStats::Result) =
					{
						return result["SMB traffic detected"]$sum;
					},
					$threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
					{
						NOTICE([$note=RANSOMWARE_SMB,
								$msg="Ransomware encrypting share detected"]);
					}]);

	Log::create_stream(FoxCryptoRansom::LOG, [$columns=Info, $path="entropy"]);
}