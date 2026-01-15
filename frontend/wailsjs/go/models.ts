export namespace model {
	
	export class EvidenceRef {
	    source_path: string;
	    offset?: number;
	    size?: number;
	    sha256?: string;
	
	    static createFrom(source: any = {}) {
	        return new EvidenceRef(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.source_path = source["source_path"];
	        this.offset = source["offset"];
	        this.size = source["size"];
	        this.sha256 = source["sha256"];
	    }
	}
	export class IOCMaterial {
	    type: string;
	    value: string;
	    note?: string;
	
	    static createFrom(source: any = {}) {
	        return new IOCMaterial(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.type = source["type"];
	        this.value = source["value"];
	        this.note = source["note"];
	    }
	}
	export class Finding {
	    id: string;
	    severity: string;
	    title: string;
	    description?: string;
	    rule_id?: string;
	    evidence_refs?: EvidenceRef[];
	    iocs?: IOCMaterial[];
	
	    static createFrom(source: any = {}) {
	        return new Finding(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.severity = source["severity"];
	        this.title = source["title"];
	        this.description = source["description"];
	        this.rule_id = source["rule_id"];
	        this.evidence_refs = this.convertValues(source["evidence_refs"], EvidenceRef);
	        this.iocs = this.convertValues(source["iocs"], IOCMaterial);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class TimelineEvent {
	    id: string;
	    // Go type: time
	    event_time: any;
	    utc_offset?: number;
	    source: string;
	    artifact: string;
	    action: string;
	    subject?: string;
	    details?: Record<string, string>;
	    confidence?: string;
	    evidence_ref: EvidenceRef;
	    ioc_hits?: string[];
	
	    static createFrom(source: any = {}) {
	        return new TimelineEvent(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.event_time = this.convertValues(source["event_time"], null);
	        this.utc_offset = source["utc_offset"];
	        this.source = source["source"];
	        this.artifact = source["artifact"];
	        this.action = source["action"];
	        this.subject = source["subject"];
	        this.details = source["details"];
	        this.confidence = source["confidence"];
	        this.evidence_ref = this.convertValues(source["evidence_ref"], EvidenceRef);
	        this.ioc_hits = source["ioc_hits"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

