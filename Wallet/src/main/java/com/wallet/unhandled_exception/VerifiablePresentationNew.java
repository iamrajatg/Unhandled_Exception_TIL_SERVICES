package com.wallet.unhandled_exception;

import com.danubetech.verifiablecredentials.VerifiableCredential;
import com.danubetech.verifiablecredentials.VerifiablePresentation;

public class VerifiablePresentationNew extends VerifiablePresentation{
	public VerifiablePresentationNew() {
		super();
	}
	
	public static class BuilderNew extends VerifiablePresentation.Builder{

		private VerifiableCredential[] verifiableCredentialList = null;

		public BuilderNew(VerifiablePresentation jsonLdObject) {
			super(jsonLdObject);
			// TODO Auto-generated constructor stub
		}
		
		public BuilderNew verifiableCredential(VerifiableCredential[] vc) {
			this.verifiableCredentialList = vc;
			return (BuilderNew) this;
		}
		
		@Override
		public VerifiablePresentationNew build() {

			super.build();

			// add JSON-LD properties
			if(verifiableCredentialList!=null) {
				for(int i=0;i<verifiableCredentialList.length;i++) {
					this.verifiableCredentialList[i].addToJsonLDObject(this.jsonLdObject);
				}
			}
			return (VerifiablePresentationNew) this.jsonLdObject;
		}
		
		
	}
	public static BuilderNew buildernew() {
		return new BuilderNew(new VerifiablePresentationNew());
	}

}
