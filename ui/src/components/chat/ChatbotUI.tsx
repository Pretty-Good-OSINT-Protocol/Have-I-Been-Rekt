
import { useState, useRef, useEffect } from "react";
import { MessageSquare } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

type Message = {
  id: string;
  text: string;
  sender: "user" | "ai";
  typing?: boolean;
};

interface ChatbotUIProps {
  walletAddress?: string;
  className?: string;
}

export function ChatbotUI({ walletAddress, className }: ChatbotUIProps) {
  const [isOpen, setIsOpen] = useState(true); // Default to open
  const [messages, setMessages] = useState<Message[]>([
    {
      id: "welcome",
      text: "Hi there! I'm your Been Rekt assistant. I can help with basic information and answer questions about crypto security. Submit the form above for a wallet analysis.",
      sender: "ai",
    },
  ]);
  const [userInput, setUserInput] = useState("");

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const chatContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (walletAddress) {
      const systemMessages = [
        {
          id: "analyzing",
          text: "We're analyzing your wallet using our basic tier tools...",
          sender: "ai" as const,
          typing: true,
        },
        {
          id: "preliminary",
          text: `Initial analysis of ${walletAddress.slice(0, 6)}...${walletAddress.slice(-4)} complete. This basic scan uses our offline database of known patterns.`,
          sender: "ai" as const,
        },
        {
          id: "upgrade",
          text: "For a comprehensive investigation with our full toolkit, you can upgrade to our premium tier. Your session data is temporary and will not be retained after you leave.",
          sender: "ai" as const,
        },
      ];

      let delay = 500;
      systemMessages.forEach((msg) => {
        setTimeout(() => {
          setMessages((prev) => [...prev, msg]);
          
          // After a delay, remove the typing indicator
          if (msg.typing) {
            setTimeout(() => {
              setMessages((prev) => 
                prev.map(m => m.id === msg.id ? { ...m, typing: false } : m)
              );
            }, 2000);
          }
        }, delay);
        delay += 3000;
      });
    }
  }, [walletAddress]);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  const handleSendMessage = () => {
    if (!userInput.trim()) return;
    
    const userMessage = {
      id: `user-${Date.now()}`,
      text: userInput,
      sender: "user" as const,
    };
    
    setMessages((prev) => [...prev, userMessage]);
    setUserInput("");
    
    // Simulate AI response for basic questions
    setTimeout(() => {
      let response = {
        id: `ai-${Date.now()}`,
        text: "I can answer basic questions about crypto security for free. For detailed investigations or using external APIs, premium features may be required.",
        sender: "ai" as const,
      };
      
      // Simple Q&A logic for basic questions
      const lowerCaseInput = userInput.toLowerCase();
      if (lowerCaseInput.includes("what is") && lowerCaseInput.includes("scam")) {
        response.text = "Crypto scams typically involve deception to steal your funds or private keys. Common types include phishing, fake ICOs, pump and dump schemes, and fake exchanges.";
      } else if (lowerCaseInput.includes("protect") && lowerCaseInput.includes("wallet")) {
        response.text = "To protect your wallet: use hardware wallets, enable 2FA, never share private keys, verify all transaction details, and be cautious of phishing attempts.";
      } else if (lowerCaseInput.includes("what") && lowerCaseInput.includes("premium")) {
        response.text = "Our premium tier provides in-depth investigation using advanced tools, API integrations, and personalized analysis. It helps uncover complex scams and provides detailed recovery recommendations.";
      }
      
      setMessages((prev) => [...prev, response]);
    }, 1000);
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  return (
    <div className={cn("w-full max-w-6xl mx-auto mt-8 mb-12 px-4", className)}>
      <div className="bg-gradient-to-r from-hibr-accent/10 to-hibr-secondary/10 p-4 rounded-lg mb-4">
        <h3 className="text-xl font-semibold text-center mb-2 text-hibr-accent">Been Rekt Assistant</h3>
        <p className="text-sm text-center text-hibr-muted-foreground">
          Our assistant can answer basic questions for free. Advanced investigations using APIs or specialized tools will require premium access.
          We'll clearly indicate when features have associated costs for recovery.
        </p>
      </div>
      
      <div 
        ref={chatContainerRef}
        className="bg-hibr-muted rounded-2xl shadow-lg overflow-hidden border border-hibr-accent"
      >
        <div className="p-3 bg-hibr-bg border-b border-hibr-accent">
          <h3 className="font-bold text-hibr-accent flex items-center gap-2">
            <MessageSquare className="h-5 w-5" />
            Chat Assistant
          </h3>
        </div>

        <div className="flex-1 overflow-y-auto p-3 max-h-[400px] min-h-[300px]">
          {messages.map((message) => (
            <div
              key={message.id}
              className={cn(
                "chat-bubble",
                message.sender === "ai"
                  ? "chat-bubble-ai"
                  : "chat-bubble-user"
              )}
            >
              {message.typing ? (
                <div className="flex gap-1 items-center">
                  <div className="w-2 h-2 bg-hibr-accent rounded-full animate-bounce"></div>
                  <div className="w-2 h-2 bg-hibr-accent rounded-full animate-bounce" style={{ animationDelay: "0.2s" }}></div>
                  <div className="w-2 h-2 bg-hibr-accent rounded-full animate-bounce" style={{ animationDelay: "0.4s" }}></div>
                </div>
              ) : (
                message.text
              )}
            </div>
          ))}
          <div ref={messagesEndRef} />
        </div>

        <div className="p-3 border-t border-hibr-accent bg-hibr-bg">
          <div className="flex items-center gap-2">
            <input
              type="text"
              placeholder="Ask a question about crypto security..."
              className="flex-1 bg-hibr-muted p-2 rounded border border-hibr-accent focus:border-hibr-secondary outline-none"
              value={userInput}
              onChange={(e) => setUserInput(e.target.value)}
              onKeyPress={handleKeyPress}
            />
            <Button 
              onClick={handleSendMessage}
              className="bg-hibr-accent text-black hover:bg-hibr-secondary"
            >
              Send
            </Button>
          </div>
          <p className="text-xs text-hibr-muted-foreground mt-1">
            Free for basic questions. Premium tier required for detailed investigations.
          </p>
        </div>
      </div>
    </div>
  );
}
