# fromAppStore
Checks if an application is pristine (untampered) and from the official Mac App Store
For technical details, see the blog post; ["Are you from the Mac App Store?"](https://objective-see.com/blog/blog_0x10.html)

Code inspired by: [RVNReceiptValidation](https://gist.github.com/sazameki/3026845)

```
$ /fromAppStore /Applications/1Password.app
checking if 1Password.app is from the OS X App Store
app is signed with an Apple Dev. ID
found receipt at: /Applications/1Password.app/Contents/_MASReceipt/receipt

check 1 passed: bundle ID's match
check 2 passed: app versions match
check 3 passed: hashes match
verfied app's receipt; it's from the OS X App Store!
```
