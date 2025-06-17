
import { useState } from "react";
import { WalletCheckForm, WalletFormData } from "@/components/wallet-check/WalletCheckForm";
import { ChatbotUI } from "@/components/chat/ChatbotUI";
import { Header } from "@/components/layout/Header";
import { Github, CreditCard, Bitcoin } from "lucide-react";
import { Card, CardHeader, CardContent, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Dialog, DialogTrigger, DialogContent, DialogTitle, DialogDescription } from "@/components/ui/dialog";

const Index = () => {
  const [submittedWallet, setSubmittedWallet] = useState<string | undefined>();

  const handleFormSubmit = (data: WalletFormData) => {
    console.log("Form submitted with data:", data);
    setSubmittedWallet(data.walletAddress);
    
    // This is where you would make an API call to your backend
    // For the MVP, we'll just set the wallet address to trigger the chatbot
  };

  return (
    <div className="min-h-screen flex flex-col">
      <Header />

      <main className="flex-1 container max-w-6xl mx-auto py-8 px-4 md:px-0">
        <section className="mb-12 text-center">
          <h1 className="text-4xl md:text-5xl font-extrabold mb-4 text-white">
            Have I Been <span className="text-hibr-accent">REKT</span><span className="text-hibr-secondary">?</span>
          </h1>
          <p className="text-xl mb-8 max-w-3xl mx-auto text-hibr-muted-foreground">
            Think your wallet's been drained? We help you figure out what happened —
            safely, privately, and with tiered service options.
          </p>
        </section>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-20">
          <div className="col-span-1 md:col-span-2 lg:col-span-1 md:order-2">
            <div className="space-y-4">
              <div className="bg-hibr-muted p-6 rounded-lg shadow-lg border border-hibr-accent">
                <h2 className="text-2xl font-bold mb-4 text-hibr-accent">About Been Rekt</h2>
                <p className="mb-4">
                  The Blockchain OSINT Toolkit for:
                </p>
                <ul className="list-disc pl-5 space-y-2 text-hibr-muted-foreground">
                  <li>Open source onchain investigation tools</li>
                  <li>Scam detection/investigations for web3</li>
                  <li>Immutable, non-alterable data sharing for journalists and researchers <span className="text-hibr-accent">(Coming Soon)</span></li>
                </ul>
                <div className="mt-4 flex items-center space-x-2">
                  <Github className="h-5 w-5 text-hibr-accent" />
                  <a 
                    href="https://github.com/Pretty-Good-OSINT-Protocol/Have-I-Been-Rekt" 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="text-hibr-accent hover:text-hibr-secondary transition-colors"
                  >
                    View on GitHub
                  </a>
                </div>
              </div>

              <div className="bg-hibr-muted p-6 rounded-lg shadow-lg border border-hibr-accent">
                <h2 className="text-2xl font-bold mb-4 text-hibr-accent">Privacy First</h2>
                <p className="text-hibr-muted-foreground">
                  This tool uses local analysis and AI to check your wallet. Your data
                  stays private and is never stored on our servers. Each session runs in an isolated 
                  environment that's discarded after use.
                </p>
                <p className="text-hibr-muted-foreground mt-2">
                  <span className="text-hibr-accent font-semibold">Coming Soon:</span> Persistent sessions and advanced investigation features.
                </p>
              </div>
            </div>
          </div>

          <div className="col-span-1 md:col-span-2 lg:col-span-1 md:order-1">
            <WalletCheckForm onFormSubmit={handleFormSubmit} />
          </div>
        </div>

        {/* ChatbotUI is now integrated directly into the page */}
        <ChatbotUI walletAddress={submittedWallet} />
        
        {/* Payment Options Section - Preparing for integration */}
        <section className="mb-12">
          <h2 className="text-3xl font-bold mb-6 text-center">Payment Options <span className="text-sm text-hibr-accent">(Coming Soon)</span></h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card className="bg-hibr-muted border-hibr-accent">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <CreditCard className="h-5 w-5 text-hibr-accent" />
                  Credit Card Payment
                </CardTitle>
                <CardDescription>Simple and convenient payment option</CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-hibr-muted-foreground mb-4">
                  Pay with credit card for premium features and in-depth investigations.
                </p>
                <Dialog>
                  <DialogTrigger asChild>
                    <Button disabled className="w-full bg-hibr-accent text-black hover:bg-hibr-secondary">
                      Pay with Card (Coming Soon)
                    </Button>
                  </DialogTrigger>
                  <DialogContent>
                    <DialogTitle>Credit Card Payment</DialogTitle>
                    <DialogDescription>
                      Credit card payments will be processed securely via Stripe. This feature is coming soon!
                    </DialogDescription>
                  </DialogContent>
                </Dialog>
              </CardContent>
            </Card>
            
            <Card className="bg-hibr-muted border-hibr-accent">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Bitcoin className="h-5 w-5 text-hibr-accent" />
                  Crypto Payment
                </CardTitle>
                <CardDescription>Privacy-preserving payment option</CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-hibr-muted-foreground mb-4">
                  Pay with cryptocurrency for enhanced privacy and convenience.
                </p>
                <Dialog>
                  <DialogTrigger asChild>
                    <Button disabled className="w-full bg-hibr-accent text-black hover:bg-hibr-secondary">
                      Pay with Crypto (Coming Soon)
                    </Button>
                  </DialogTrigger>
                  <DialogContent>
                    <DialogTitle>Crypto Payment</DialogTitle>
                    <DialogDescription>
                      Privacy-preserving cryptocurrency payments will be available soon. We're working on integrating Holonym for regulatory compliance without sacrificing privacy.
                    </DialogDescription>
                  </DialogContent>
                </Dialog>
              </CardContent>
            </Card>
          </div>
        </section>
      </main>

      <footer className="py-6 bg-hibr-bg border-t border-hibr-muted text-center">
        <div className="container">
          <p className="text-hibr-muted-foreground">
            © 2023 Pretty Good OSINT Protocol | 
            <a href="#" className="text-hibr-accent ml-1 hover:text-hibr-secondary">
              Privacy Policy
            </a>
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Index;
