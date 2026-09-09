import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import numpy as np

class AutoencoderModel(nn.Module):
    def __init__(self, input_dim):
        super(AutoencoderModel, self).__init__()
        
        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, int(input_dim * 0.75)),
            nn.ReLU(True),
            nn.Linear(int(input_dim * 0.75), int(input_dim * 0.5)),
            nn.ReLU(True),
            nn.Linear(int(input_dim * 0.5), int(input_dim * 0.25)),
            nn.ReLU(True)
        )
        
        
        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(int(input_dim * 0.25), int(input_dim * 0.5)),
            nn.ReLU(True),
            nn.Linear(int(input_dim * 0.5), int(input_dim * 0.75)),
            nn.ReLU(True),
            nn.Linear(int(input_dim * 0.75), input_dim),
            # Linear output for standardization (can use Sigmoid if MinMax scaled)
        )

    def forward(self, x):
        x = self.encoder(x)
        x = self.decoder(x)
        return x

class MavisAutoencoder:
    def __init__(self, input_dim, learning_rate=1e-3, device='cpu'):
        self.device = torch.device(device)
        self.model = AutoencoderModel(input_dim).to(self.device)
        self.criterion = nn.MSELoss()
        self.optimizer = optim.Adam(self.model.parameters(), lr=learning_rate)
        self.is_trained = False
        
    def fit(self, X_train, epochs=20, batch_size=256):
        """Train the Autoencoder on benign traffic.

        Renamed from 'train' to avoid shadowing nn.Module.train().
        """
        print("Training Deep Autoencoder...")
        X_tensor = torch.FloatTensor(X_train.values).to(self.device)
        dataset = TensorDataset(X_tensor, X_tensor)
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
        
        self.model.train()
        for epoch in range(epochs):
            total_loss = 0
            for batch_x, _ in dataloader:
                self.optimizer.zero_grad()
                reconstructed = self.model(batch_x)
                loss = self.criterion(reconstructed, batch_x)
                loss.backward()
                self.optimizer.step()
                total_loss += loss.item()
                
            print(f"Epoch {epoch+1}/{epochs}, Loss: {total_loss/len(dataloader):.6f}")
            
        self.is_trained = True
        print("Training complete.")

    def train(self, X_train, epochs=20, batch_size=256):
        """Backward-compatible alias for fit()."""
        return self.fit(X_train, epochs=epochs, batch_size=batch_size)
        
    def predict_anomaly_score(self, X):
        """
        Returns the reconstruction error as the anomaly score.
        High error = high likelihood of anomaly.
        """
        if not self.is_trained:
            raise ValueError("Model is not trained yet.")
            
        self.model.eval()
        X_tensor = torch.FloatTensor(X.values).to(self.device)
        with torch.no_grad():
            reconstructed = self.model(X_tensor)
            
        # Compute MSE per sample
        mse = torch.mean((X_tensor - reconstructed) ** 2, dim=1)
        return mse.cpu().numpy()
        
    def save(self, filepath):
        torch.save(self.model.state_dict(), filepath)
        
    def load(self, filepath):
        self.model.load_state_dict(torch.load(filepath, map_location=self.device))
        self.is_trained = True
