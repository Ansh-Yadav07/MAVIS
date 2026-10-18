import copy

import numpy as np
import torch
import torch.nn as nn

from ._util import to_numpy


def _dims(input_dim, fractions):
    return [max(2, int(input_dim * f)) for f in fractions]


class AutoencoderModel(nn.Module):
    def __init__(self, input_dim, hidden_fractions=(0.75, 0.5, 0.25), dropout=0.0):
        super().__init__()
        h = _dims(input_dim, hidden_fractions)
        enc, prev = [], input_dim
        for i, d in enumerate(h):
            enc += [nn.Linear(prev, d), nn.ReLU()]
            if dropout and i < len(h) - 1:
                enc.append(nn.Dropout(dropout))
            prev = d
        dec = []
        for d in list(reversed(h[:-1])) + [input_dim]:
            dec.append(nn.Linear(prev, d))
            if d != input_dim:
                dec.append(nn.ReLU())
            prev = d
        self.encoder, self.decoder = nn.Sequential(*enc), nn.Sequential(*dec)

    def forward(self, x):
        return self.decoder(self.encoder(x))


class MavisAutoencoder:
    def __init__(self, input_dim, learning_rate=1e-3, device='cpu', hidden_fractions=(0.75, 0.5, 0.25),
                 dropout=0.0, noise_std=0.0, weight_decay=0.0, seed=42):
        self.input_dim = int(input_dim)
        self.config = dict(learning_rate=learning_rate, hidden_fractions=tuple(hidden_fractions),
                           dropout=dropout, noise_std=noise_std, weight_decay=weight_decay, seed=seed)
        self.device = torch.device(device)
        torch.manual_seed(seed)
        self.model = AutoencoderModel(self.input_dim, self.config['hidden_fractions'], dropout).to(self.device)
        self.is_trained = False
        self.history = {'train': [], 'val': []}

    def _tensor(self, X):
        arr = to_numpy(X)
        if arr.shape[1] != self.input_dim:
            raise ValueError(f"expected {self.input_dim} features, got {arr.shape[1]}")
        return torch.from_numpy(np.ascontiguousarray(arr))

    @torch.no_grad()
    def _val_loss(self, X_val, batch_size=8192):
        self.model.eval()
        tot = 0.0
        for i in range(0, len(X_val), batch_size):
            b = X_val[i:i + batch_size].to(self.device)
            tot += ((self.model(b) - b) ** 2).sum().item()
        return tot / X_val.numel()

    def fit(self, X, X_val=None, epochs=20, batch_size=256, patience=None):
        """Train on benign traffic. If X_val is given, keep the best-val-loss weights and
        stop after `patience` epochs without improvement (patience=None -> never stop early)."""
        print("Training Deep Autoencoder...")
        cfg = self.config
        gen = torch.Generator().manual_seed(cfg['seed'])
        Xt = self._tensor(X).to(self.device)
        Xv = self._tensor(X_val) if X_val is not None else None
        opt = torch.optim.Adam(self.model.parameters(), lr=cfg['learning_rate'], weight_decay=cfg['weight_decay'])
        sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=max(1, epochs), eta_min=cfg['learning_rate'] * 0.05)
        n, best, best_state, bad = len(Xt), float('inf'), None, 0
        self.history = {'train': [], 'val': []}
        for epoch in range(epochs):
            self.model.train()
            perm = torch.randperm(n, generator=gen).to(self.device)
            total, nb = 0.0, 0
            for i in range(0, n, batch_size):
                b = Xt[perm[i:i + batch_size]]
                inp = b + cfg['noise_std'] * torch.randn_like(b) if cfg['noise_std'] else b
                loss = ((self.model(inp) - b) ** 2).mean()
                opt.zero_grad()
                loss.backward()
                opt.step()
                total += loss.item()
                nb += 1
            sched.step()
            self.history['train'].append(total / nb)
            msg = f"Epoch {epoch + 1}/{epochs}, Loss: {total / nb:.6f}"
            if Xv is not None:
                v = self._val_loss(Xv)
                self.history['val'].append(v)
                msg += f", Val: {v:.6f}"
                if v < best - 1e-6:
                    best, bad = v, 0
                    best_state = copy.deepcopy(self.model.state_dict())
                else:
                    bad += 1
            print(msg)
            if Xv is not None and patience is not None and bad >= patience:
                print(f"Early stopping at epoch {epoch + 1}")
                break
        if best_state is not None:
            self.model.load_state_dict(best_state)
        self.is_trained = True
        print("Training complete.")
        return self

    def train(self, X_train, epochs=20, batch_size=256, X_val=None, patience=None):
        """Backward-compatible alias for fit()."""
        return self.fit(X_train, X_val=X_val, epochs=epochs, batch_size=batch_size, patience=patience)

    @torch.no_grad()
    def _errors(self, X, batch_size, reduce):
        if not self.is_trained:
            raise ValueError("Model is not trained yet.")
        self.model.eval()
        arr = to_numpy(X)
        if arr.shape[1] != self.input_dim:
            raise ValueError(f"expected {self.input_dim} features, got {arr.shape[1]}")
        out = []
        for i in range(0, len(arr), batch_size):
            b = torch.from_numpy(np.ascontiguousarray(arr[i:i + batch_size])).to(self.device)
            e = (self.model(b) - b) ** 2
            out.append((e.mean(dim=1) if reduce else e).cpu().numpy())
        if not out:
            return np.zeros(0 if reduce else (0, self.input_dim))
        return np.concatenate(out)

    def predict_anomaly_score(self, X, batch_size=65_536):
        """1-D float array of mean squared reconstruction error; higher = more anomalous."""
        return self._errors(X, batch_size, True).astype(np.float64)

    def feature_errors(self, X, batch_size=65_536):
        """(n_rows, n_features) per-feature squared reconstruction error; row mean == anomaly score."""
        return self._errors(X, batch_size, False)

    def save(self, filepath):
        torch.save({'input_dim': self.input_dim, 'config': self.config,
                    'state_dict': self.model.state_dict()}, filepath)

    @classmethod
    def load(cls, filepath, device='cpu'):
        ckpt = torch.load(filepath, map_location=device)
        inst = cls(ckpt['input_dim'], device=device, **ckpt['config'])
        inst.model.load_state_dict(ckpt['state_dict'])
        inst.is_trained = True
        return inst
