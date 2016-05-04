//
//  main.h
//  fromAppStore
//
//  Created by Patrick Wardle on 5/1/16.
//

#ifndef main_h
#define main_h

@class AppReceipt;
#import <Foundation/Foundation.h>


/* FUNCTIONS */

//verify signature
// ->must be signed with Apple Dev ID/cert
BOOL verifySignature(NSString* appPath);

//verify the receipt
// ->check bundle ID, app version, and receipt's hash
BOOL verifyReceipt(NSString* appPath, AppReceipt* receipt);

//get GUID
// ->from Apple's 'Get the GUID in OS X' (see: 'Validating Receipts Locally')
NSData* getGUID();


#endif /* main_h */
