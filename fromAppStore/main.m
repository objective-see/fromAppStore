//
//  main.m
//  fromAppStore
//
//  Created by Patrick Wardle on 5/1/16.
//

#import "main.h"
#import "AppReceipt.h"

//main
int main(int argc, const char * argv[])
{
    @autoreleasepool
    {
        //app path
        NSString* appPath = nil;
        
        //app receipt
        AppReceipt* appReceipt = nil;
        
        //check args
        if(2 != argc)
        {
            //err msg
            NSLog(@"ERROR: invalid usage; you must provide an app bundle");
            
            //bail
            goto bail;
        }
        
        //init app path
        appPath = [NSString stringWithUTF8String:argv[1]];
        
        //dbg msg
        NSLog(@"checking if %@ is from the Mac App Store", [appPath lastPathComponent]);
        
        //first make sure its signed with an Apple Dev ID
        if(YES != verifySignature(appPath))
        {
            //err msg
            NSLog(@"ERROR: failed to verify app signature");
            
            //bail
            goto bail;
        }
        
        //dbg msg
        NSLog(@"app is signed with an Apple Dev. ID");
        
        //init
        // ->will parse/decode, etc
        appReceipt = [[AppReceipt alloc] init:appPath];
        if(nil == appReceipt)
        {
            //err msg
            NSLog(@"ERROR: failed to init/decode/parse app's receipt");
        
            //bail
            goto bail;
        }
        
        //verify
        if(YES != verifyReceipt(appPath, appReceipt))
        {
            //err msg
            NSLog(@"ERROR: failed to verify app's receipt");
            
            //bail
            goto bail;
        }
        
        //dbg msg
        NSLog(@"verified app's receipt; it's from the Mac App Store!");
    }
    
//bail
bail:
    
    return 0;
}

//verify signature
// ->must be signed with Apple Dev ID/cert
BOOL verifySignature(NSString* appPath)
{
    //flag
    BOOL signedOK = NO;
    
    //code
    SecStaticCodeRef staticCode = NULL;
    
    //signing reqs
    SecRequirementRef requirementRef = NULL;
    
    //status
    OSStatus status = -1;
    
    //create static code
    status = SecStaticCodeCreateWithPath((__bridge CFURLRef)([NSURL fileURLWithPath:appPath]), kSecCSDefaultFlags, &staticCode);
    if(noErr != status)
    {
        //err msg
        NSLog(@"ERROR: SecStaticCodeCreateWithPath() failed with %d", status);
        
        //bail
        goto bail;
    }
    
    //create req string w/ 'anchor apple generic'
    status = SecRequirementCreateWithString(CFSTR("anchor apple generic"), kSecCSDefaultFlags, &requirementRef);
    if( (noErr != status) ||
        (requirementRef == NULL) )
    {
        //err msg
        NSLog(@"ERROR: SecRequirementCreateWithString() failed with %d", status);
        
        //bail
        goto bail;
    }
    
    //check if file is signed w/ apple dev id by checking if it conforms to req string
    status = SecStaticCodeCheckValidity(staticCode, kSecCSDefaultFlags, requirementRef);
    if(noErr != status)
    {
        //err msg
        NSLog(@"ERROR: SecStaticCodeCheckValidity() failed with %d", status);
        
        //bail
        // ->just means app isn't signed by apple dev id
        goto bail;
    }
    
    //ok, happy
    // ->file is signed by Apple Dev ID
    signedOK = YES;
    
//bail
bail:
    
    //free req reference
    if(NULL != requirementRef)
    {
        //free
        CFRelease(requirementRef);
    }
    
    //free static code
    if(NULL != staticCode)
    {
        //free
        CFRelease(staticCode);
    }
    
    return signedOK;
}

//verify the receipt
// ->check bundle ID, app version, and receipt's hash
BOOL verifyReceipt(NSString* appPath, AppReceipt* receipt)
{
    //flag
    BOOL verified = NO;
    
    //app bundle
    NSBundle* appBundle = nil;
    
    //guid
    NSData* guid = nil;
    
    //hash data
    NSMutableData *digestData = nil;
    
    //hash buffer
    unsigned char digestBuffer[CC_SHA1_DIGEST_LENGTH] = {0};
    
    //load bundle
    appBundle = [NSBundle bundleWithPath:appPath];
    if(nil == appBundle)
    {
        //bail
        goto bail;
    }
    
    //check guid
    guid = getGUID();
    if(nil == guid)
    {
        //err msg
        NSLog(@"ERROR: failed to determine GUID");
        
        //bail
        goto bail;
    }
    
    //create data obj
    digestData = [NSMutableData data];
    
    //add guid to data obj
    [digestData appendData:guid];
    
    //add receipt's 'opaque value' to data obj
    [digestData appendData:receipt.opaqueValue];
    
    //add receipt's bundle id data to data obj
    [digestData appendData:receipt.bundleIdentifierData];

    //CHECK 1:
    // ->app's bundle ID should match receipt's bundle ID
    if(YES != [receipt.bundleIdentifier isEqualToString:appBundle.bundleIdentifier])
    {
        //err msg
        NSLog(@"ERROR: receipt's bundle ID (%@) != app's bundle ID (%@)", receipt.bundleIdentifier, appBundle.bundleIdentifier);

        //bail
        goto bail;
    }
    
    //dbg msg
    NSLog(@"check 1 passed: bundle ID's match");
    
    //CHECK 2:
    // ->app's version should match receipt's version
    if(YES != [receipt.appVersion isEqualToString:appBundle.infoDictionary[@"CFBundleShortVersionString"]])
    {
        //err msg
        NSLog(@"ERROR: receipt's app version (%@) != app's version (%@)", receipt.appVersion, appBundle.infoDictionary[@"CFBundleShortVersionString"]);
        
        //bail
        goto bail;
    }
    
    //dbg msg
    NSLog(@"check 2 passed: app versions match");
    
    //CHECK 3:
    // ->verify receipt's hash (UUID)
    
    //init SHA 1 hash
    CC_SHA1(digestData.bytes, (CC_LONG)digestData.length, digestBuffer);
    
    //check for hash match
    if(0 != memcmp(digestBuffer, receipt.receiptHash.bytes, CC_SHA1_DIGEST_LENGTH))
    {
        //err msg
        NSLog(@"ERROR: receipt's hash does not match computed one");
        
        //hash check failed
        goto bail;
    }
    
    //dbg msg
    NSLog(@"check 3 passed: hashes match");
    
    //happy
    verified = YES;

//bail
bail:
    
    return verified;
}

//get GUID (really just computer's MAC address)
// ->from Apple's 'Get the GUID in OS X' (see: 'Validating Receipts Locally')
NSData* getGUID()
{
    kern_return_t  kernResult = -1;
    mach_port_t    master_port = 0;
    CFMutableDictionaryRef  matchingDict = NULL;
    io_iterator_t iterator = 0;
    io_object_t service = 0;
    CFDataRef  registryProperty = NULL;
    
    //guid (MAC addr)
    NSData *guid = nil;
    
    //get master port
    kernResult = IOMasterPort(MACH_PORT_NULL, &master_port);
    if(KERN_SUCCESS != kernResult)
    {
        //bail
        goto bail;
    }
    
    //get matching dictionary for 'en0'
    matchingDict = IOBSDNameMatching(master_port, 0, "en0");
    if(NULL == matchingDict)
    {
        //bail
        goto bail;
    }
    
    //get matching services
    kernResult = IOServiceGetMatchingServices(master_port, matchingDict, &iterator);
    if(KERN_SUCCESS != kernResult)
    {
        //bail
        goto bail;
    }
    
    //iterate over services, looking for 'IOMACAddress'
    while((service = IOIteratorNext(iterator)) != 0)
    {
        //parent
        io_object_t parentService = 0;
        
        //get parent
        kernResult = IORegistryEntryGetParentEntry(service, kIOServicePlane, &parentService);
        if(KERN_SUCCESS == kernResult)
        {
            //release prev
            if(NULL != registryProperty)
            {
                //release
                CFRelease(registryProperty);
            }
            
            //get registry property for 'IOMACAddress'
            registryProperty = (CFDataRef) IORegistryEntryCreateCFProperty(parentService, CFSTR("IOMACAddress"), kCFAllocatorDefault, 0);
            
            //release parent
            IOObjectRelease(parentService);
        }
        
        //release service
        IOObjectRelease(service);
    }
    
    //release iterator
    IOObjectRelease(iterator);
    
    //convert guid to NSData*
    // ->also release registry property
    if(NULL != registryProperty)
    {
        //convert
        guid = [NSData dataWithData:(__bridge NSData *)registryProperty];
        
        //release
        CFRelease(registryProperty);
    }

//bail
bail:

    return guid;
}
